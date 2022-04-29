// use concurrent_queue::ConcurrentQueue;
// use rb::{Consumer, Producer, SpscRb};
use snafu::ensure;

use std::{
    cmp::{max, min},
    collections::VecDeque,
    fmt,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::{Duration, Instant},
};

use crate::protocol::{
    network::ip_packet::*,
    tcp::{control_buffers::*, tcp_errors::*, *},
};

pub const MSS: usize = 536; // TODO: RFC 1122, p. 86 says "MUST" default of 536
pub const ALPHA: f64 = 0.85;
pub const BETA: f64 = 1.5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TCPState {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    CloseWait,
    TimeWait,
    LastAck,
}

impl TCPState {
    pub fn readable(&self) -> bool {
        *self == TCPState::Established || *self == TCPState::FinWait1 || *self == TCPState::FinWait2
    }

    pub fn writable(&self) -> bool {
        *self == TCPState::Established || *self == TCPState::CloseWait
    }

    pub fn should_send_ack(&self) -> bool {
        *self == TCPState::Established || *self == TCPState::FinWait2
    }

    pub fn can_delete(&self) -> bool {
        *self == TCPState::Listen || *self == TCPState::SynSent
    }

    pub fn can_shutdown(&self) -> bool {
        *self == TCPState::SynRcvd || *self == TCPState::Established || *self == TCPState::CloseWait
    }

    pub fn closing(&self) -> bool {
        *self == TCPState::FinWait1
            || *self == TCPState::FinWait2
            // || *self == TCPState::Closing // is closing necessary here?
            || *self == TCPState::LastAck
    }
}

impl fmt::Display for TCPState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match &*self {
                TCPState::Listen => "LISTEN",
                TCPState::SynSent => "SYN SENT",
                TCPState::SynRcvd => "SYN RCVD",
                TCPState::Established => "ESTAB",
                TCPState::FinWait1 => "FIN WAIT 1",
                TCPState::FinWait2 => "FIN WAIT 2",
                TCPState::Closing => "CLOSING",
                TCPState::CloseWait => "CLOSE WAIT",
                TCPState::TimeWait => "TIME WAIT",
                TCPState::LastAck => "LAST ACK",
            }
        )
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum ShutdownType {
    Write,
    Read,
    Both,
}

pub struct SegmentEntry {
    pub segment: TCPSegment,
    pub send_time: Instant,
    pub counter: usize,
}

#[derive(Clone)]
pub struct Socket {
    pub src_sock: SocketAddrV4,
    pub dst_sock: SocketAddrV4,
    pub tcp_state: Arc<Mutex<TCPState>>,

    // timer for timewait
    pub time_wait: Arc<Mutex<Option<Instant>>>,
    // timer for zero probing
    pub zero_probe: Arc<Mutex<Option<Instant>>>,
    pub zp_counter: Arc<AtomicU8>,
    // re-transmission timer, by Jacobson's + Karn's algorithm
    pub prtt: Arc<Mutex<Duration>>,
    // keep track of last time sent for RTT
    pub time_sent: Arc<Mutex<Option<Instant>>>,
    // queue for retransmitting segmants
    pub rtx_q: Arc<Mutex<VecDeque<SegmentEntry>>>,

    // Send/Receive Control Structs
    pub snd: Arc<Mutex<SendControlBuffer>>,
    pub rcv: Arc<Mutex<RecvControlBuffer>>,
    send_tx: SyncSender<IPPacket>,
    nagles: Arc<AtomicBool>,

    // Mark as read closed
    pub r_closed: Arc<AtomicBool>,
}

impl Socket {
    pub fn new(
        src_sock: SocketAddrV4,
        dst_sock: SocketAddrV4,
        tcp_state: TCPState,
        send_tx: SyncSender<IPPacket>,
    ) -> Socket {
        Socket {
            src_sock,
            dst_sock,
            tcp_state: Arc::new(Mutex::new(tcp_state)),
            // timer information
            time_wait: Arc::new(Mutex::new(None)),
            zero_probe: Arc::new(Mutex::new(None)),
            zp_counter: Arc::new(AtomicU8::new(0)),
            prtt: Arc::new(Mutex::new(Duration::from_millis(1))),
            time_sent: Arc::new(Mutex::new(None)),
            //
            rtx_q: Arc::new(Mutex::new(VecDeque::new())),
            //
            snd: Arc::new(Mutex::new(SendControlBuffer::new())),
            rcv: Arc::new(Mutex::new(RecvControlBuffer::new())),
            send_tx,
            nagles: Arc::new(AtomicBool::new(false)),
            //
            r_closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /**
     * Receives data from the other end of the connection.
     */
    pub fn recv_buffer(&self, buf: &mut [u8], n_bytes: usize) -> TCPResult<usize> {
        // if closed, automatically return 0
        if self.r_closed.load(Ordering::Relaxed) {
            return Ok(0);
        }

        // if invalid state, immediately return
        let tcp_state = self.get_tcp_state();
        ensure!(
            tcp_state.readable(),
            InvalidStateSnafu {
                tcp_state,
                command: String::from("RECV"),
            }
        );

        let mut rcv = self.rcv.lock().unwrap();

        // return number of bytes read
        match rcv.read(buf, n_bytes) {
            Some(n) => Ok(n),
            None => NoDataSnafu {
                count: 0_usize,
                num_bytes: n_bytes,
            }
            .fail(),
        }
    }

    /**
     * Sends a created segment to other end of the connection.
     */
    pub fn send_buffer(&self, buf: &[u8]) -> TCPResult<usize> {
        // if invalid state, immediately return
        let tcp_state = self.get_tcp_state();
        ensure!(
            tcp_state.writable(),
            InvalidStateSnafu {
                tcp_state,
                command: String::from("SEND"),
            }
        );

        let mut snd = self.snd.lock().unwrap();
        let old_len = snd.len();

        // attempt to write to circular buffer
        snd.write(buf)?;

        // if Nagle's algorithm is enabled, follow algorithm
        // Reference: RFC 1122, p. 98-99
        if self.nagles.load(Ordering::Relaxed) {
            // if:
            // - amount of data in queue >= MSS
            // - there was no unconfirmed data, automatically send
            if snd.len() >= MSS || old_len == 0 {
                let segments = snd.get_una_segments(MSS);
                self.send_segments(segments).unwrap();
            } // else { // otherwise, just buffer, which we've already done with snd.write }
        } else {
            // if no Nagle's, just send immediately
            let segments = snd.get_una_segments(MSS);
            self.send_segments(segments).unwrap();
        }

        Ok(buf.len())
    }

    /**
     * Sends all un-ACK'd data up until the window.
     */
    pub fn send_segments(&self, segments: Vec<(u32, Vec<u8>)>) -> Result<()> {
        // for each segment, create TCP segment/IP packet
        for (seg_seq, seg_data) in segments {
            println!(
                "Sending segment with SEQ {} and size {}",
                seg_seq,
                seg_data.len()
            );

            let (ack, win_sz) = RecvControlBuffer::get_rcv_ack(self.rcv.clone());
            let segment =
                TCPSegment::new(self.src_sock, self.dst_sock, seg_seq, ack, win_sz, seg_data);

            self.send(segment, true, 0)?;
        }
        Ok(())
    }

    /**
     * Gets the amount of space left in the send buffer.
     */
    pub fn get_space_left(&self) -> usize {
        self.snd.lock().unwrap().space_left()
    }

    /**
     * Gets the number of bytes available in the recv buffer.
     */
    pub fn get_rcv_len(&self) -> usize {
        self.rcv.lock().unwrap().len()
    }

    /**
     * Sends a SYN segment to the destination.
     */
    pub fn send_syn(&self, dst_sock: SocketAddrV4, iss: u32) -> Result<()> {
        println!("[{}] sending SYN to {}...", self.src_sock, dst_sock);

        // create TCP segment/IP packet
        let segment = TCPSegment::new_syn(self.src_sock, dst_sock, iss);

        self.send(segment, true, 0)
    }

    /**
     * Sends a SYN+ACK segment to other end of connection.
     */
    pub fn send_syn_ack(&self, snd_iss: u32, rcv_nxt: u32, win_sz: u16) -> Result<()> {
        println!(
            "[{}] sending SYN+ACK to {}...",
            self.src_sock, self.dst_sock
        );

        // create TCP segment/IP packet
        let segment =
            TCPSegment::new_syn_ack(self.src_sock, self.dst_sock, snd_iss, rcv_nxt, win_sz);
        self.send(segment, true, 0)
    }

    /**
     * Sends an ACK segment to other end of connection. [TODO: piggyback off data, if possible]
     */
    pub fn send_ack(&self, snd_nxt: u32, rcv_nxt: u32, win_sz: u16) -> Result<()> {
        println!("[{}] sending ACK to {}...", self.src_sock, self.dst_sock);
        // create TCP segment/IP packet
        let segment = TCPSegment::new(
            self.src_sock,
            self.dst_sock,
            snd_nxt,
            rcv_nxt,
            win_sz,
            Vec::new(),
        );
        self.send(segment, false, 0)
    }

    /**
     * Sends a FIN segment to the other end of connection, signaling we will no longer write.
     */
    pub fn send_fin(&self) -> Result<()> {
        println!("[{}] sending FIN to {}...", self.src_sock, self.dst_sock);

        // get SEQ: should be byte after last byte sent (i.e. SND.NXT)
        let seq = {
            let mut snd = self.snd.lock().unwrap();
            let old_nxt = snd.nxt;
            snd.nxt += 1;
            old_nxt
        };

        // get ACK and WIN_SZ
        let (ack, win_sz) = RecvControlBuffer::get_rcv_ack(self.rcv.clone());

        // make segment and packet
        let segment = TCPSegment::new_fin(self.src_sock, self.dst_sock, seq, ack, win_sz);
        self.send(segment, true, 0)
    }

    /**
     * Generic send function for sending TCP segment
     */
    pub fn send(&self, segment: TCPSegment, retransmit: bool, counter: usize) -> Result<()> {
        let mut rtx_q = self.rtx_q.lock().unwrap();
        let packet = IPPacket::new(
            *self.src_sock.ip(),
            *self.dst_sock.ip(),
            segment.to_bytes()?,
            TCP_TTL,
            TCP_PROTOCOL,
        );

        // add to retransmission queue if retransmit
        if retransmit {
            rtx_q.push_back(SegmentEntry {
                segment,
                send_time: Instant::now(),
                counter,
            })
        }

        if self.send_tx.send(packet).is_ok() {}

        Ok(())
    }

    /**
     * Updates the IRTT given a new RTT.
     *
     * Inputs:
     * - the time receiving the packet
     */
    pub fn update_prtt(&self, rtt: Instant) {
        let mut time_sent = self.time_sent.lock().unwrap();
        if *time_sent == None {
            return;
        }
        let mut prtt = self.prtt.lock().unwrap();
        *prtt = prtt.mul_f64(ALPHA) + rtt.duration_since(time_sent.unwrap()).mul_f64(1.0 - ALPHA);
        *time_sent = None;
    }

    /**
     * Checks whether the socket has time sent.
     */
    pub fn has_time_sent(&self) -> bool {
        *self.time_sent.lock().unwrap() != None
    }

    /**
     * Computes the RTO of the socket, from the PRTT.
     *
     * Returns:
     * - the computed re-transmission timeout
     */
    pub fn get_rto(&self) -> Duration {
        // because constant Durations are nightly only...
        let (lbound, ubound) = (Duration::from_millis(1), Duration::from_millis(100));
        let prtt = self.prtt.lock().unwrap();
        min(ubound, max(lbound, prtt.mul_f64(BETA)))
    }

    /**
     * Gets the current state of the TCP socket.
     */
    pub fn get_tcp_state(&self) -> TCPState {
        self.tcp_state.lock().unwrap().clone()
    }

    /**
     * Sets the state of the TCP socket.
     */
    pub fn set_tcp_state(&mut self, state: TCPState) {
        let mut tcp_state = self.tcp_state.lock().unwrap();
        *tcp_state = state;
    }

    /**
     * Checks if read end is closed.
     */
    pub fn r_closed(&self) -> bool {
        self.r_closed.load(Ordering::Relaxed)
    }

    pub fn clear_retransmissions(&self) {
        let una = self.snd.lock().unwrap().una;
        let rtx_q = self.rtx_q.clone();
        let mut rtx_q = rtx_q.lock().unwrap();

        // for all packets in the queue who have completely been acknowledged, remove
        while !rtx_q.is_empty() {
            let rtx_seg = rtx_q.front().unwrap();
            let rtx_seg_end =
                rtx_seg.segment.header.sequence_number + rtx_seg.segment.data.len() as u32;
            if rtx_seg_end < una {
                rtx_q.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn pop_rtx_front(&self) -> Option<SegmentEntry> {
        let rtx_q = self.rtx_q.clone();
        let mut rtx_q = rtx_q.lock().unwrap();
        rtx_q.pop_front()
    }
}
