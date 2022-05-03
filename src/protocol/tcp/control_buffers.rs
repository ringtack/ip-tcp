use crate::protocol::tcp::tcp_errors::*;
use snafu::ensure;

use std::{
    cmp::{max, min},
    fmt,
    sync::{Arc, Condvar, Mutex},
};

pub const SEQ_MAX: u32 = u32::MAX;
pub const BUFFER_SIZE: usize = u16::MAX as usize;
// pub const BUFFER_SIZE: usize = 16;
pub const BSIZE_U32: u32 = BUFFER_SIZE as u32;
pub const WIN_SZ: u16 = u16::MAX;
// pub const WIN_SZ: u16 = 8;

/**
 * Control struct containing the send sequence space's variables.
 *
 * Fields:
 * - BUF: circular buffer containing send information
 * - len: the length of the data in the buffer
 * - head: byte AFTER valid byte in buffer
 * - tail: the first valid byte in buffer
 * - cv: condition variable for threads waiting on buffer to clear up
 *
 * - UNA: the first unacknowledged byte in the send sequence
 * - NXT: the next byte to be sent
 * - WND: the window size allowed to be sent
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
    pub len: usize,
    head: usize,
    tail: usize,
    pub cv: Arc<Condvar>,
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
            cv: Arc::new(Condvar::new()),
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
     * Reads up to `count` bytes from the send buffer. Updates NXT if applicable, but not
     * UNA/tail.
     *
     * Returns:
     * - SEQ of first byte in data + num read, or None
     */
    #[allow(dead_code)]
    pub fn get_una(&mut self, data: &mut [u8], count: usize) -> Option<(u32, usize)> {
        let count = min(count, min(self.len, self.wnd as usize));
        // if no space, just return
        if count == 0 {
            return None;
        }

        let una = (self.una % BSIZE_U32) as usize;
        // we already enforce SND.UNA + count < SND.(UNA + WND)
        if una + count < BUFFER_SIZE {
            data[..count].copy_from_slice(&self.buf[una..(una + count)]);
        } else {
            let buf_bytes_left = BUFFER_SIZE - una;
            data[..buf_bytes_left].copy_from_slice(&self.buf[una..]);
            data[buf_bytes_left..count].copy_from_slice(&self.buf[..(count - buf_bytes_left)]);
        }

        // Update NXT, if applicable [TODO: this doesn't wrap around u32::MAX]
        self.nxt = max(self.una.wrapping_add(count as u32), self.nxt);

        // self.una is SEQNO of segment
        Some((self.una, count))
    }

    /**
     * Gets the byte at the end of the send window (i.e. buf[SND.UNA + SND.WND]), or None if not
     * present.
     */
    pub fn get_end(&self) -> Option<u8> {
        let end = self.nxt % BSIZE_U32;
        let end_usize = end as usize;

        assert_eq!((self.tail + self.len) % BUFFER_SIZE, self.head);
        // if end is past the head, nothing to send, so return
        if (self.head < self.tail && (self.tail <= end_usize || end_usize < self.head))
            || (self.tail <= end_usize && end_usize < self.head)
            || (self.tail == self.head && self.len > 0 && end_usize == self.head)
        {
            Some(self.buf[end_usize])
        } else {
            None
        }
    }

    /**
     * Reads up to `count` bytes from the provided position in the send buffer. Can update NXT,
     * but not UNA/tail.
     *
     * Inputs:
     * - pos: SEQUENCE NUMBER (not buffer pos!)
     */
    #[allow(dead_code)]
    pub fn get_pos(&mut self, pos: usize, data: &mut [u8], count: usize) -> Option<(u32, usize)> {
        let pos = pos as u32;
        if !self.in_una_window(pos) {
            return None;
        }
        let off = pos % BSIZE_U32 - self.una;
        self.get_off(off as usize, data, count)
    }

    /**
     * Reads up to `count` bytes from the provided offset from SND.UNA in the send buffer. Can
     * update NXT, but not UNA/tail.
     *
     * Returns:
     * - SEQ of first byte in data, or None if invalid offset
     */
    pub fn get_off(&mut self, off: usize, data: &mut [u8], count: usize) -> Option<(u32, usize)> {
        // get starting position; if not in (2), return None
        let start = self.una as usize + off;
        let start_u32 = start as u32;

        let bytes_left = self.bytes_left(start % BUFFER_SIZE);
        if !self.in_una_window(start_u32) || bytes_left == 0 {
            // eprintln!("[get_off] no more to send");
            return None;
        }

        // shrink count to the number available
        let count = min(
            min(count, bytes_left), // cannot get more than # of relevant bytes left
            self.una_wnd_size() as usize - off, // or number of bytes left in RCV window
        );
        // eprintln!("[SCB::get_off] count: {count}");

        // convert SEQ -> BUF space
        let start_buf = start % BUFFER_SIZE;

        // we already enforce SND.NXT + count < SND.(UNA + WND)
        if start_buf + count < BUFFER_SIZE {
            data[..count].copy_from_slice(&self.buf[start_buf..(start_buf + count)]);
        } else {
            let buf_bytes_left = BUFFER_SIZE - start_buf;
            data[..buf_bytes_left].copy_from_slice(&self.buf[start_buf..]);
            data[buf_bytes_left..count].copy_from_slice(&self.buf[..(count - buf_bytes_left)]);
        }

        // Update NXT, if applicable [TODO: this doesn't handle the wrap around u32::MAX]
        self.nxt = max(self.nxt, start.wrapping_add(count) as u32);

        // println!("[SCB::get_nxt] {}", self);

        Some((start_u32, count))
    }

    /**
     * Gets all un-ACK'd segments from the buffer.
     */
    #[allow(dead_code)]
    pub fn get_una_segments(&mut self, seg_size: usize) -> Vec<(u32, Vec<u8>)> {
        self.get_off_segments(0, seg_size)
    }

    /**
     * Gets all not yet sent segments from the buffer.
     */
    pub fn get_nxt_segments(&mut self, seg_size: usize) -> Vec<(u32, Vec<u8>)> {
        self.get_off_segments(self.nxt.wrapping_sub(self.una) as usize, seg_size)
    }

    /**
     * Gets all un-ACK'd segments from the buffer, starting from the provided offset.
     */
    pub fn get_off_segments(&mut self, off: usize, seg_size: usize) -> Vec<(u32, Vec<u8>)> {
        let mut segments = Vec::new();

        // validate start position
        let start_u32 = self.una.wrapping_add(off as u32);
        let start = start_u32 as usize;
        if !self.in_una_window(start_u32) {
            // if invalid, return empty Vec
            return segments;
        };

        // compute number to read
        let to_read = min(
            self.una_wnd_size() as usize - off, // bytes left in RCV'ing buffer's window
            self.bytes_left(start % BUFFER_SIZE), // relevant bytes left in actual buffer
        );

        // eprintln!("[SCB::get_off_segments] to_read: {}", to_read);

        let mut n_read = 0;
        // while there's still stuff to read
        while n_read < to_read {
            // get segment chunk!
            let mut segment = vec![0; seg_size];

            // println!(
            // "[SCB::get_una_segments] segment.len(): {}, num_bytes: {}",
            // segment.len(),
            // num_bytes
            // );

            // read up to seg_size of data (n_got will return actual amount)
            let (seg_seq, n_got) =
                match self.get_off(off + n_read, segment.as_mut_slice(), seg_size) {
                    Some((ss, ng)) => (ss, ng),
                    None => {
                        // eprintln!("breaking");
                        break;
                    } // theoretically, should never reach here
                };

            // resize to actual amount
            segment.resize(n_got, 0);
            // update control values
            n_read += n_got;
            // to_read -= n_got;
            segments.push((seg_seq, segment));

            // eprintln!("[SCB::get_off_segments] n_read: {n_read}");
        }

        // update SND.NXT to the amount read (which should be == end)
        self.nxt = start.wrapping_add(n_read) as u32;

        segments
    }

    /**
     * Fills the circular buffer with the specified slice of data. If not enough space, returns
     * without filling the buffer.
     *
     * [Philosophy: reads should always work, since we want to send *UP TO* the end of the data in
     * the stream; however, when filling up the buffer, we don't want only part of our write
     * operation to succeed; the stream may be mangled.]
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
            msg_len <= self.capacity(),
            MsgSizeSnafu {
                msg_len,
                max_len: self.capacity(),
            }
        );
        // if no space left, return error
        ensure!(
            self.space_left() > 0,
            NoBufsSnafu {
                msg_len,
                remaining_len: self.space_left() as usize,
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

        // eprintln!("[SCB::write] {}", self);

        Ok(msg_len)
    }

    /**
     * Gets the end position of the Send sequence space (i.e. SND.UNA + SND.WND).
     */
    pub fn snd_end(&self) -> u32 {
        self.una.wrapping_add(self.wnd as u32)
    }

    /**
     * Sets initial sequence and all other related values (UNA, NXT, head, tail)
     *
     * Inputs:
     * - isn: the chosen initial sequence number
     */
    pub fn set_iss(&mut self, iss: u32) {
        self.iss = iss;
        self.una = iss;
        self.nxt = iss + 1;

        self.head = ((iss + 1) % BSIZE_U32) as usize;
        self.tail = ((iss + 1) % BSIZE_U32) as usize;
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
        // NOTE: because all SCBs are hidden behind mutexes, we can safely signal the CV here
        // without performing additional synchronization.
        if self.is_full() {
            self.cv.notify_all()
        }

        if self.wl1 < seq_no || (self.wl1 == seq_no && self.wl2 < ack_no) {
            self.wnd = seg_wnd;
            self.wl1 = seq_no;
            self.wl2 = ack_no;
        }

        let diff = self.una_nxt_size();
        let num_acked = if ack_no > self.una {
            ack_no - self.una
        } else {
            ack_no + SEQ_MAX - self.una
        };
        self.una = ack_no;
        // only update nxt if more was ACKed
        self.nxt = if diff > num_acked { self.nxt } else { ack_no };

        // incremented last acknowledgment, so can "remove" from send buffer
        self.tail = self.una as usize % BUFFER_SIZE;
        self.len -= num_acked as usize;

        // remove from retransmission queue [do this in handler]

        num_acked
    }

    /**
     * Checks if the ACKNO is of currently un-ACK'd data (i.e. section (2)).
     *
     * Inputs:
     * - ack_no: the SEG.ACK of a segment
     */
    pub fn in_una_nxt_window(&self, ack_no: u32) -> bool {
        // println!("[SCB::in_una_window] ack_no: {}, {}", ack_no, self);

        if self.nxt >= self.una {
            self.una <= ack_no && ack_no <= self.nxt
        } else {
            (self.una <= ack_no && ack_no < SEQ_MAX) || ack_no <= self.nxt
        }
    }

    /**
     * Checks if the ACKNO is in the UNA window (i.e. sections (2) + (3))
     */
    pub fn in_una_window(&self, ack_no: u32) -> bool {
        if self.snd_end() < self.una {
            self.una <= ack_no && ack_no < SEQ_MAX || ack_no < self.snd_end()
        } else {
            self.una <= ack_no && ack_no < self.snd_end()
        }
    }

    /**
     * Gets the size difference between NXT and UNA, i.e. (2) in the diagram.
     */
    pub fn una_nxt_size(&self) -> u32 {
        if self.nxt >= self.una {
            self.nxt - self.una
        } else {
            self.nxt + SEQ_MAX - self.una
        }
    }

    /**
     * Gets the window size allowed for new transmission [NXT..UNA+WND], i.e. (3) in the diagram
     */
    pub fn nxt_wnd_size(&self) -> u32 {
        if self.snd_end() < self.nxt {
            self.snd_end() + SEQ_MAX - self.nxt
        } else {
            self.snd_end() - self.nxt
        }
    }

    /**
     * Gets the total window size allowed [UNA..UNA+WND], i.e. (2) + (3) in the diagram
     */
    pub fn una_wnd_size(&self) -> u32 {
        self.una_nxt_size() + self.nxt_wnd_size()
    }

    /**
     * Checks if buffer is empty.
     */
    #[allow(dead_code)]
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
     * Returns number of relevant bytes left in send buffer, from position. (BUF INDEX)
     */
    pub fn bytes_left(&self, b_pos: usize) -> usize {
        // eprintln!(
        // "[SCB::bytes_left] head: {}, bpos: {}, tail: {}",
        // self.head, b_pos, self.tail
        // );

        if self.head == self.tail {
            if self.len == 0 {
                0
            } else {
                self.head + self.len - b_pos
            }
        } else if self.tail < self.head {
            if b_pos < self.tail || b_pos >= self.head {
                0
            } else {
                self.head - b_pos
            }
        } else if self.head <= b_pos && b_pos < self.tail {
            0
        } else if b_pos <= self.head {
            self.head - b_pos
        } else {
            self.head + BUFFER_SIZE - b_pos
        }

        // eprintln!("[SCB::bytes_left] {bytes_left}");
        // bytes_left
    }

    /**
     * Returns how much space is left in the send buffer.
     */
    pub fn space_left(&self) -> usize {
        // if self.tail > self.head {
        // self.tail - self.head
        // } else {
        // BUFFER_SIZE - self.head + self.tail
        // }
        BUFFER_SIZE - self.len // lol right??? what am I doing
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
 * - len: the length of the data in the buffer
 * - head: byte AFTER last valid byte in buffer
 * - tail: first valid byte in buffer
 * - cv: condition variable for threads waiting for content to arrive
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
    pub cv: Arc<Condvar>,
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
            cv: Arc::new(Condvar::new()),
            nxt: 0,
            wnd: WIN_SZ,
            up: 0,
            irs: 0,
        }
    }

    /**
     * Reads acknowledged bytes from the circular buffer. Updates tail, wnd, and len.
     */
    pub fn read(&mut self, data: &mut [u8], count: usize) -> Option<usize> {
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
            return None;
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

        Some(count)
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
            // eprintln!(
            // "[RCB::write] SEQ {} out of range [{}, {}]",
            // seq_no,
            // self.nxt,
            // self.nxt + self.wnd as u32
            // );
            return Ok(0);
        }

        // get only the relevant data
        let diff = self.nxt.wrapping_sub(seq_no) as usize % BUFFER_SIZE;
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

        // if previously empty, notify any waiters
        if self.is_empty() {
            self.cv.notify_all();
        }

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
        self.nxt = self.nxt.wrapping_add(msg_len as u32);
        self.wnd -= msg_len as u16;
        self.len += msg_len;

        // println!("[RCB::write] {}", self);

        Ok(msg_len)
    }

    /**
     * Sets initial receive number and all other related values (NXT, head, tail)
     *
     * Inputs:
     * - irs: the initial receive number (i.e. SEG.SEQ of SYN segment)
     */
    pub fn set_irs(&mut self, irs: u32) {
        self.irs = irs;
        self.nxt = irs + 1;

        self.len = 0;
        self.head = (irs + 1) as usize % BUFFER_SIZE;
        self.tail = (irs + 1) as usize % BUFFER_SIZE;
    }

    /**
     * Sets NXT, and all other associated values (len, head, TODO: which)
     *
     * Inputs:
     * - nxt: next SEQ value received
     */
    #[allow(dead_code)]
    pub fn set_nxt(&mut self, nxt: u32) {
        self.len += nxt.wrapping_sub(self.nxt) as usize;
        self.head = nxt as usize % BUFFER_SIZE;

        self.nxt = nxt;
    }

    /**
     * Gets the end of the receive window, in SEQNO space.
     */
    pub fn rcv_end(&self) -> u32 {
        self.nxt.wrapping_add(self.wnd as u32)
    }

    /**
     * Checks if a sequence number is in the receive window.
     *
     * Inputs:
     * - seq_no: the desired receive number
     */
    pub fn in_window(&self, seq_no: u32) -> bool {
        if self.nxt < self.rcv_end() {
            self.nxt <= seq_no && seq_no <= self.rcv_end()
        } else {
            self.nxt <= seq_no || seq_no < self.rcv_end()
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
        (this.nxt, this.wnd)
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
