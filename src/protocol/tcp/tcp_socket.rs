use crate::protocol::{link::MTU, network::ip_packet::*, tcp::*};

use std::fmt;

pub const BUF_SIZE: u16 = u16::MAX;
// -20 for size of TCP Header without options
pub const MSS: usize = MTU - 20;

#[derive(Clone, PartialEq, Eq)]
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

#[derive(Clone)]
pub struct Socket {
    pub src_sock: SocketAddrV4,
    pub dst_sock: SocketAddrV4,
    pub tcp_state: Arc<Mutex<TCPState>>,

    // Send/Receive Control Variables
    pub seg: Arc<Mutex<SegmentVariables>>,
    pub snd: Arc<Mutex<SendSequence>>,
    pub rcv: Arc<Mutex<RecvSequence>>,

    // Send/Receive Buffers/Channels
    send_tx: SyncSender<IPPacket>,
    // send_buffer (TODO: what size?)
    // recv_buffer (TODO: what size?)
    // retransmit_queue (TODO: which data structure?)
    // current_segment (TODO: what needs to be represented?)
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
            seg: Arc::new(Mutex::new(SegmentVariables::new())),
            snd: Arc::new(Mutex::new(SendSequence::new())),
            rcv: Arc::new(Mutex::new(RecvSequence::new())),
            send_tx,
        }
    }

    /**
     * Sends a SYN segment to the destination.
     */
    pub fn send_syn(&self, dst_sock: SocketAddrV4, iss: u32) -> Result<()> {
        println!("[{}] sending SYN to {}...", self.src_sock, self.dst_sock);

        // create TCP segment/IP packet
        let segment = TCPSegment::new_syn(self.src_sock, dst_sock, iss);
        let packet = IPPacket::new(
            *self.src_sock.ip(),
            *dst_sock.ip(),
            segment.to_bytes()?,
            TCP_TTL,
            TCP_PROTOCOL,
        );

        // send to channel to process
        if self.send_tx.send(packet).is_ok() {}
        Ok(())
    }

    /**
     * Sends a SYN+ACK segment to other end of connection.
     */
    pub fn send_syn_ack(&self, snd_iss: u32, rcv_nxt: u32) -> Result<()> {
        println!(
            "[{}] sending SYN+ACK to {}...",
            self.src_sock, self.dst_sock
        );

        // create TCP segment/IP packet
        let segment =
            TCPSegment::new_syn_ack(self.src_sock, self.dst_sock, snd_iss, rcv_nxt, WIN_SZ);
        let packet = IPPacket::new(
            *self.src_sock.ip(),
            *self.dst_sock.ip(),
            segment.to_bytes()?,
            TCP_TTL,
            TCP_PROTOCOL,
        );

        // send to channel to process
        if self.send_tx.send(packet).is_ok() {}
        Ok(())
    }

    /**
     * Sends an ACK segment to other end of connection. [TODO: piggyback off data, if possible]
     */
    pub fn send_ack(&self, sync: bool, snd_una: u32, snd_nxt: u32, rcv_nxt: u32) -> Result<()> {
        let segment = if sync {
            println!(
                "[{}] !!!SYNC!!! sending SYN+ACK to {}...",
                self.src_sock, self.dst_sock
            );
            // if synchronous, SEQ = ISS = SND.UNA, and send SYN+ACK
            TCPSegment::new_syn_ack(self.src_sock, self.dst_sock, snd_una, rcv_nxt, WIN_SZ)
        } else {
            println!("[{}] sending ACK to {}...", self.src_sock, self.dst_sock);
            // otherwise, SEQ = SND.NXT, and send ACK [TODO: plus piggyback data, if possible]
            TCPSegment::new(
                self.src_sock,
                self.dst_sock,
                snd_nxt,
                rcv_nxt,
                WIN_SZ,
                Vec::new(),
            )
        };
        // create IP packet
        let packet = IPPacket::new(
            *self.src_sock.ip(),
            *self.dst_sock.ip(),
            segment.to_bytes()?,
            TCP_TTL,
            TCP_PROTOCOL,
        );

        // send to channel to process
        if self.send_tx.send(packet).is_ok() {}
        Ok(())
    }
}

/**
 * Struct containing the current segment variables.
 *
 * Fields:
 * - SEQ: segment sequence number (SEQ of first byte)
 * - ACK: acknowledgment number from receiver (i.e. next SEQ expected)
 * - LEN: segment length (including SYN/FIN)
 * - WND: receiver's window (TODO: why need here?)
 * - UP: segment's urgent pointer (UNUSED)
 * - PRC: segment's precedence (UNUSED)
 */
#[derive(Clone)]
pub struct SegmentVariables {
    pub seq: u32,
    pub ack: u32,
    pub len: u16,
    pub wnd: u16,
    pub up: u16,
    pub prc: u16,
}

impl SegmentVariables {
    pub fn new() -> SegmentVariables {
        SegmentVariables {
            seq: 0,
            ack: 0,
            len: 0,
            wnd: 0,
            up: 0,
            prc: 0,
        }
    }
}

/**
 * Struct containing the send sequence space's variables.
 *
 * Fields:
 * - UNA: the first unacknowledged byte in the send sequence
 * - NXT: the next byte to be sent
 * - WND: the window size allowed to be sent
 * - UP: the urgent pointer (UNUSED)
 * - WL1: segment sequence number for the last window update (TODO: what is this?)
 * - WL2: segment acknowledgment number used for the last window update (TODO: ^)
 * - ISS: initial send sequence number (ISN)
 *
 * Send Sequence Space Diagram:
 *                 1         2          3          4
 *            ----------|----------|----------|----------
 *                   SND.UNA    SND.NXT    SND.UNA
 *                                        +SND.WND
 *
 *      1 - old sequence numbers which have been acknowledged
 *      2 - sequence numbers of unacknowledged data
 *      3 - sequence numbers allowed for new data transmission
 *      4 - future sequence numbers which are not yet allowed
 */
#[derive(Clone)]
pub struct SendSequence {
    pub una: u32,
    pub nxt: u32,
    pub wnd: u16,
    pub up: u16,
    pub wl1: u32,
    pub wl2: u32,
    pub iss: u32,
}

impl SendSequence {
    pub fn new() -> SendSequence {
        SendSequence {
            una: 0,
            nxt: 0,
            wnd: 0,
            up: 0,
            wl1: 0,
            wl2: 0,
            iss: 0,
        }
    }
}

/**
 * Struct containing the receive sequence space's variables.
 *
 * Fields:
 * - NXT: the next byte (sequence number) to receive
 * - WND: the window size allowed to be received
 * - UP: the urgent pointer (UNUSED)
 * - IRS: initial receive sequence number
 *
 * Receive Sequence Space Diagram:
 *
 *                      1          2          3
 *                 ----------|----------|----------
 *                        RCV.NXT    RCV.NXT
 *                                  +RCV.WND
 *
 *      1 - old sequence numbers which have been acknowledged
 *      2 - sequence numbers allowed for new reception
 *      3 - future sequence numbers which are not yet allowed
 */
#[derive(Clone)]
pub struct RecvSequence {
    pub nxt: u32,
    pub wnd: u16,
    pub up: u16,
    pub irs: u32,
}

impl RecvSequence {
    pub fn new() -> RecvSequence {
        RecvSequence {
            nxt: 0,
            wnd: 0,
            up: 0,
            irs: 0,
        }
    }
}
