use crate::protocol::tcp::{tcp_errors::*, tcp_socket::WIN_SZ, *};
use snafu::ensure;

use std::{
    cmp::{max, min},
    fmt,
    sync::{Arc, Mutex},
};

pub const BUFFER_SIZE: usize = u16::MAX as usize;
// pub const BUFFER_SIZE: usize = 16;

/**
 * Control struct containing the send sequence space's variables.
 *
 * Fields:
 * - BUF: circular buffer containing send information
 * - len: the length of the data in the buffer
 * - head: byte AFTER valid byte in buffer
 * - tail: the first valid byte in buffer
 *
 * - UNA: the first unacknowledged byte in the send sequence [NB: this is the buffer's head!]
 * - NXT: the next byte to be sent
 * - WND: the window size allowed to be sent [NB: UNA+WND is the buffer's tail!]
 * - UP: the urgent pointer (UNUSED)
 * - WL1: segment sequence number for the last window update (TODO: what is this?)
 * - WL2: segment acknowledgment number used for the last window update (TODO: ^)
 * - ISS: initial send sequence number (ISN)
 *
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
// #[derive(Clone)]
pub struct SendControlBuffer {
    pub buf: [u8; BUFFER_SIZE],
    len: usize,
    head: usize,
    tail: usize,
    pub una: u32,
    pub nxt: u32,
    pub wnd: u16,
    pub up: u16,
    pub wl1: u32,
    pub wl2: u32,
    pub iss: u32,
}

impl SendControlBuffer {
    pub fn new() -> SendControlBuffer {
        SendControlBuffer {
            buf: [0; BUFFER_SIZE],
            len: 0,
            head: 0,
            tail: 0,
            una: 0,
            nxt: 0,
            wnd: 0,
            up: 0,
            wl1: 0,
            wl2: 0,
            iss: 0,
        }
    }

    /**
     * Attempts to read count bytes from send buffer's UNA. Updates NXT if applicable, but not
     * UNA/tail.
     *
     * Returns:
     * - SEQ of first byte in data, or Error
     */
    pub fn get_una(&mut self, data: &mut [u8], count: usize) -> TCPResult<u32> {
        // check that there's enough data to read, and request isn't too large
        ensure!(
            count <= self.len && count <= self.wnd as usize,
            NoDataSnafu {
                count,
                num_bytes: min(self.len, self.wnd as usize),
            }
        );

        let una = self.una as usize;
        // we already enforce SND.UNA + count < SND.(UNA + WND)
        if una + count < BUFFER_SIZE {
            data[..count].copy_from_slice(&self.buf[una..(una + count)]);
        } else {
            let buf_bytes_left = BUFFER_SIZE - una;
            data[..buf_bytes_left].copy_from_slice(&self.buf[una..]);
            data[buf_bytes_left..count].copy_from_slice(&self.buf[..(count - buf_bytes_left)]);
        }

        // update nxt
        self.nxt = max(self.nxt, (self.una + count as u32) % BUFFER_SIZE as u32);

        Ok(self.una)
    }

    /**
     * Attempts to read count bytes from send buffer's NXT. Updates NXT, but not UNA/tail.
     *
     * Returns:
     * - SEQ of first byte in data, or Error
     */
    pub fn get_nxt(&mut self, data: &mut [u8], count: usize) -> TCPResult<(u32, usize)> {
        let num_readable = min(self.len, self.window_nxt() as usize);
        // shrink count to the number available
        let count = min(count, min(self.len, self.window_nxt() as usize));

        ensure!(
            count <= num_readable,
            NoDataSnafu {
                count,
                num_bytes: num_readable,
            }
        );

        // get count bytes
        let nxt = self.nxt as usize;
        // we already enforce SND.NXT + count < SND.(UNA + WND)
        if nxt + count < BUFFER_SIZE {
            data[..count].copy_from_slice(&self.buf[nxt..(nxt + count)]);
        } else {
            let buf_bytes_left = BUFFER_SIZE - nxt;
            data[..buf_bytes_left].copy_from_slice(&self.buf[nxt..]);
            data[buf_bytes_left..count].copy_from_slice(&self.buf[..(count - buf_bytes_left)]);
        }

        let seq_no = self.nxt;
        // update nxt
        self.nxt = (self.nxt + count as u32) % BUFFER_SIZE as u32;

        // println!("[SCB::get_nxt] {}", self);

        Ok((seq_no, count))
    }

    /**
     * Gets all un-ACK'd segments from the buffer.
     */
    pub fn get_una_segments(&mut self, seg_size: usize) -> TCPResult<Vec<(u32, Vec<u8>)>> {
        let mut segments = Vec::new();
        // temporarily update NXT, to interoperate with get_nxt
        let old_nxt = self.nxt;
        let diff = self.diff_nxt_una() as usize;
        self.nxt = self.una;

        let mut n_read = 0;
        // while there's still stuff to read
        while self.window_nxt() > 0 {
            let num_bytes = min(seg_size, self.window_nxt() as usize);
            // get segment chunk!
            let mut segment = vec![0; num_bytes];

            // println!(
            // "[SCB::get_una_segments] segment.len(): {}, num_bytes: {}",
            // segment.len(),
            // num_bytes
            // );

            // stop once we hit WND
            let (seg_seq, n_got) = match self.get_nxt(segment.as_mut_slice(), num_bytes) {
                Ok((seg_seq, n_got)) => (seg_seq, n_got),
                Err(_) => break,
            };

            segment.resize(n_got, 0);
            // update control values
            n_read += n_got;
            segments.push((seg_seq, segment));

            // if num gotten is less than num_bytes, break
            if n_got < num_bytes {
                break;
            }
        }
        // reset NXT if not enough read [TODO: emit an error]
        self.nxt = if diff >= n_read { old_nxt } else { self.nxt };

        Ok(segments)
    }

    /**
     * Updates tail/una pointer by specified number of bytes (i.e. "consumes" those bytes!) by
     * acknowledging them.
     *
     * TODO: do I really need, if I update tail and length in set_una?
     */
    pub fn skip_una(&mut self, count: usize) -> TCPResult<()> {
        // check that there's enough data to jump forward by
        ensure!(
            count <= self.len && count <= self.wnd as usize,
            NoDataSnafu {
                count,
                num_bytes: self.len
            }
        );

        self.tail += count;
        // also this is probably wrong
        self.nxt += count as u32;

        Ok(())
    }

    /**
     * Fills the circular buffer with the specified slice of data. If not enough space, returns
     * without filling the buffer.
     *
     * Inputs:
     * - data: a slice of data
     *
     * Returns:
     * - status of write (error message, or number of bytes written)
     */
    pub fn write(&mut self, data: &[u8]) -> TCPResult<usize> {
        let msg_len = data.len();
        // ensure not above capacity
        ensure!(
            msg_len <= BUFFER_SIZE,
            MsgSizeSnafu {
                msg_len,
                max_len: BUFFER_SIZE,
            }
        );
        // ensure not more than possible
        ensure!(
            msg_len <= self.space_left() as usize,
            NoBufsSnafu {
                msg_len,
                remaining_len: self.space_left() as usize,
            }
        );

        // println!("[SCB::write] msg_len: {}", msg_len);

        // check if can write without wrapping
        if self.head + msg_len < BUFFER_SIZE {
            self.buf[self.head..(self.head + msg_len)].copy_from_slice(data);
        } else {
            // otherwise, first copy into what's left
            let buf_bytes_left = BUFFER_SIZE - self.head;
            self.buf[self.head..BUFFER_SIZE].copy_from_slice(&data[..buf_bytes_left]);
            // then, copy remainder of message into start
            self.buf[..(msg_len - buf_bytes_left)].copy_from_slice(&data[buf_bytes_left..]);
        }

        // update head and len
        self.head = (self.head + msg_len) % BUFFER_SIZE;
        self.len += msg_len;

        // println!("[SCB::write] {}", self);
        // TODO: notify condition variable? or do within sock.send

        Ok(msg_len)
    }

    /**
     * Sets initial sequence and all other related values (UNA, NXT, head, tail)
     *
     * Inputs:
     * - isn: the chosen initial sequence number
     */
    pub fn set_iss(&mut self, iss: u32) {
        let b_size = BUFFER_SIZE as u32;
        self.iss = iss % b_size;
        self.una = iss % b_size;
        self.nxt = (iss + 1) % b_size;

        self.head = ((iss + 1) % b_size) as usize;
        self.tail = ((iss + 1) % b_size) as usize;
        self.len = 1; // hacky solution to let set_una through
    }

    /**
     * Sets UNA and other associated values (UNA, NXT?, WND, WL1, WL2, len, tail)
     *
     * Inputs:
     * - seq_no: the sequence number for window updating
     * - ack_no: the acknowledgment number to update the UNA to
     * - seg_wnd: the specified window size
     *
     * Returns:
     * - number of bytes that became acknowledged
     *
     * Reference: RFC 793, p. 72
     */
    pub fn set_una(&mut self, seq_no: u32, ack_no: u32, seg_wnd: u16) -> u32 {
        if self.wl1 < seq_no || (self.wl1 == seq_no && self.wl2 < ack_no) {
            self.wnd = seg_wnd;
            self.wl1 = seq_no;
            self.wl2 = ack_no;
        }

        let diff = self.diff_nxt_una();
        let num_acked = (BUFFER_SIZE as u32 + ack_no - self.una) % BUFFER_SIZE as u32;
        self.una = ack_no;
        // only update nxt if more was ACKed
        self.nxt = if diff > num_acked { ack_no } else { self.nxt };

        // incremented last acknowledgment, so can "remove" from send buffer
        self.tail = self.una as usize;
        self.len -= num_acked as usize;

        // TODO: remove from retransmission queue

        num_acked
    }

    /**
     * Checks if the ACKNO is of currently un-ACK'd data (i.e. section 2 in the above picture).
     *
     * Inputs:
     * - ack_no: the SEG.ACK of a segment
     */
    pub fn in_una_window(&self, ack_no: u32) -> bool {
        // println!("[SCB::in_una_window] ack_no: {}, {}", ack_no, self);

        if self.nxt >= self.una {
            self.una <= ack_no && ack_no <= self.nxt
        } else {
            (self.una <= ack_no && ack_no < BUFFER_SIZE as u32) || ack_no <= self.nxt
        }
    }

    /**
     * Gets the size difference between NXT and UNA, i.e. (2) in the diagram.
     */
    pub fn diff_nxt_una(&self) -> u32 {
        if self.nxt >= self.una {
            self.nxt - self.una
        } else {
            self.nxt + BUFFER_SIZE as u32 - self.una
        }
    }

    /**
     * Gets the window size allowed for new transmission [NXT..UNA+WND], i.e. (3) in the diagram
     */
    pub fn window_nxt(&self) -> u32 {
        // shouldn't have to worry about circling around, since it only gets size?
        self.una + self.wnd as u32 - self.nxt
    }

    /**
     * Checks if buffer is empty.
     */
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /**
     * Checks if buffer is full.
     */
    pub fn is_full(&self) -> bool {
        self.len > 0 && self.head == self.tail
    }

    /**
     * Returns the number of bytes in the buffer.
     */
    pub fn len(&self) -> usize {
        self.len
    }

    /**
     * Returns how much space is left.
     */
    pub fn space_left(&self) -> usize {
        if self.tail > self.head {
            self.tail - self.head
        } else {
            BUFFER_SIZE - self.head + self.tail
        }
    }

    /**
     * Returns the capacity of the buffer.
     */
    pub fn capacity(&self) -> usize {
        BUFFER_SIZE
    }
}

impl fmt::Display for SendControlBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[SCB] len: {}\thead: {}\ttail: {}\tuna: {}\tnxt: {}\twnd: {}\tup: {}\twl1: {}\twl2: {}\tiss: {}",
            self.len, self.head, self.tail, self.una, self.nxt, self.wnd, self.up, self.wl1, self.wl2, self.iss
        )
    }
}

/**
 * Control struct containing the receive sequence space's variables.
 *
 * Fields:
 * - BUF: circular buffer containing receive information
 * - len: the length of the data in the buffer [NB: NXT-LEN is the head!]
 * - head: byte AFTER last valid byte in buffer
 * - tail: first valid byte in buffer
 *
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
//#[derive(Clone)]
pub struct RecvControlBuffer {
    pub buf: [u8; BUFFER_SIZE],
    pub len: usize,
    head: usize,
    tail: usize,
    pub nxt: u32,
    pub wnd: u16,
    pub up: u16,
    pub irs: u32,
}

impl RecvControlBuffer {
    pub fn new() -> RecvControlBuffer {
        RecvControlBuffer {
            buf: [0; BUFFER_SIZE],
            len: 0,
            head: 0,
            tail: 0,
            nxt: 0,
            wnd: WIN_SZ, // TODO: what should initial window be? WIN_SZ?
            up: 0,
            irs: 0,
        }
    }

    /**
     * Reads acknowledged bytes from the circular buffer. Updates tail, wnd, and len.
     */
    pub fn read(&mut self, data: &mut [u8], count: usize) -> TCPResult<usize> {
        // check that there's enough acknowledged data to read
        // ensure!(
        // count <= self.len, // which should be the same as nxt - tail
        // NoDataSnafu {
        // count,
        // num_bytes: self.len,
        // }
        // );

        // println!("[RCB::read] count: {}", count);
        // println!("[RCB::read] before {}", self);

        let count = min(count, self.len);
        if count == 0 {
            return Ok(0);
        }

        // we already enforce that tail + count < RCV.NXT
        if self.tail + count < BUFFER_SIZE {
            data[..count].copy_from_slice(&self.buf[self.tail..(self.tail + count)]);
        } else {
            let buf_bytes_left = BUFFER_SIZE - self.tail;
            data[..buf_bytes_left].copy_from_slice(&self.buf[self.tail..]);
            data[buf_bytes_left..count].copy_from_slice(&self.buf[..(count - buf_bytes_left)]);
        }

        // update tail, wnd, and len
        self.tail = (self.tail + count) % BUFFER_SIZE;
        self.wnd += count as u16;
        self.len -= count;

        // println!("[RCB::read] {}", self);

        Ok(count)
    }

    /**
     * Fills the circular buffer with the specified slice of data. If not enough space, returns
     * without filling the buffer. Updates head (if applicable), nxt (aka ACK), wnd, and len
     *
     * Inputs:
     * - data: a slice of data
     * - seq_no: the starting SEQNO of the data
     *
     * Returns:
     * - status of write (error message, or number of bytes written)
     */
    pub fn write(&mut self, data: &[u8], seq_no: u32) -> TCPResult<usize> {
        let msg_len = data.len();
        let seg_end = seq_no + msg_len as u32;

        // TODO: currently, only accepts ----[SEQ_NO...{RCV.NXT...SEG_END]...RCV.NXT+RCV.WND}----,
        // but ideally want more flexibility
        if !((seq_no <= self.nxt || self.nxt + self.wnd as u32 <= seq_no)
            && self.in_window(seg_end))
        {
            eprintln!(
                "[RCB::write] SEQ {} out of range [{}, {}]",
                seq_no,
                self.nxt,
                self.nxt + self.wnd as u32
            );
            return Ok(0);
        }

        // get only the relevant data
        let diff = (self.nxt + BUFFER_SIZE as u32 - seq_no) as usize % BUFFER_SIZE;
        let relevant_data = &data[diff..];
        let msg_len = relevant_data.len();

        // println!("{}", self);
        // println!("[RCB::write] msg_len: {}, diff: {}", msg_len, diff);

        // ensure not above capacity
        ensure!(
            msg_len <= BUFFER_SIZE,
            MsgSizeSnafu {
                msg_len,
                max_len: BUFFER_SIZE,
            }
        );
        // ensure not more than possible to store
        ensure!(
            msg_len <= self.wnd as usize,
            NoBufsSnafu {
                msg_len,
                remaining_len: self.wnd as usize,
            }
        );

        // check if can write without wrapping
        if self.head + msg_len < BUFFER_SIZE {
            self.buf[self.head..(self.head + msg_len)].copy_from_slice(relevant_data);
        } else {
            // otherwise, first copy into what's left
            let buf_bytes_left = BUFFER_SIZE - self.head;
            self.buf[self.head..BUFFER_SIZE].copy_from_slice(&relevant_data[..buf_bytes_left]);
            // then, copy remainder of message into start
            self.buf[..(msg_len - buf_bytes_left)]
                .copy_from_slice(&relevant_data[buf_bytes_left..]);
        }

        let old_head = self.head;
        // update head, nxt (aka ACK), wnd, and len
        self.head = (old_head + msg_len) % BUFFER_SIZE;
        self.nxt = ((old_head + msg_len) % BUFFER_SIZE) as u32;
        self.wnd -= msg_len as u16;
        self.len += msg_len;

        // println!("[RCB::write] {}", self);
        // TODO: notify condition variable? or do within sock.send

        Ok(msg_len)
    }

    /**
     * Sets initial receive number and all other related values (NXT, head, tail)
     *
     * Inputs:
     * - irs: the initial receive number (i.e. SEG.SEQ of SYN segment)
     */
    pub fn set_irs(&mut self, irs: u32) {
        let b_size = BUFFER_SIZE as u32;
        self.irs = irs % b_size;
        self.nxt = (irs + 1) % b_size;

        self.len = 0;
        self.head = (irs + 1) as usize;
        self.tail = (irs + 1) as usize;
    }

    /**
     * Sets NXT, and all other associated values (len, head, TODO: which)
     *
     * Inputs:
     * - nxt: next SEQ value received
     */
    pub fn set_nxt(&mut self, nxt: u32) {
        self.len += (nxt - self.nxt) as usize;
        self.head = nxt as usize;

        self.nxt = nxt;
    }

    /**
     * Checks if a sequence number is in the receive window.
     *
     * Inputs:
     * - seq_no: the desired receive number
     */
    pub fn in_window(&self, seq_no: u32) -> bool {
        let rcv_end = (self.nxt + self.wnd as u32) % BUFFER_SIZE as u32;
        if self.nxt < rcv_end {
            self.nxt <= seq_no && seq_no <= rcv_end
        } else {
            self.nxt <= seq_no || seq_no <= rcv_end
        }
    }

    /**
     * Checks acceptability of segment (assuming in SYN_RCVD, ESTAB, etc.)
     *
     * Inputs:
     * - seq_no: sequence number of segment
     * - seg_len: the length of the segment
     *
     * From the RFC (note that 3rd and 4th conditions are flipped in implementation):
     *  Segment Receive  Test
     *  Length  Window
     *  ------- -------  -------------------------------------------
     *     0       0     SEG.SEQ = RCV.NXT
     *     0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
     *    >0       0     not acceptable
     *    >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
     *                or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
     */
    pub fn acceptable_seg(&self, seq_no: u32, seg_len: u32) -> bool {
        let (seg_zero, wnd_zero) = (seg_len == 0, self.wnd == 0);
        if seg_zero && wnd_zero {
            seq_no == self.nxt
        } else if seg_zero && !wnd_zero {
            self.in_window(seq_no)
        } else if !seg_zero && !wnd_zero {
            self.in_window(seq_no) || self.in_window(seq_no + seg_len)
        } else {
            false
        }
    }

    /**
     * Checks if buffer is empty.
     */
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /**
     * Checks if buffer is full.
     */
    pub fn is_full(&self) -> bool {
        self.len > 0 && self.head == self.tail
    }

    /**
     * Returns the number of bytes in the buffer.
     */
    pub fn len(&self) -> usize {
        self.len
    }

    /**
     * Returns how much space is left.
     */
    pub fn space_left(&self) -> usize {
        if self.tail > self.head {
            self.tail - self.head
        } else {
            BUFFER_SIZE - self.head + self.tail
        }
    }

    /**
     * Returns the capacity of the buffer.
     */
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /**
     * Gets the current ACK'd value (from behind a lock)
     *
     * Returns:
     * - (ack, win_size)
     */
    pub fn get_rcv_ack(this: Arc<Mutex<Self>>) -> (u32, u16) {
        let this = this.lock().unwrap();
        (
            // ((this.nxt as usize + BUFFER_SIZE - 1) % BUFFER_SIZE) as u32,
            this.nxt, this.wnd,
        )
    }
}

impl fmt::Display for RecvControlBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[RCB] len: {}\thead: {}\ttail: {}\tnxt: {}\twnd: {}\tup: {}\tirs: {}",
            self.len, self.head, self.tail, self.nxt, self.wnd, self.up, self.irs
        )
    }
}
