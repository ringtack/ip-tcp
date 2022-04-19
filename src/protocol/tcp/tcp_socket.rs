use crate::protocol::link::MTU;
use std::net::SocketAddrV4;

pub const BUF_SIZE: u16 = u16::MAX;
// -20 for size of TCP Header without options
pub const MSS: usize = MTU - 20;

#[derive(Clone)]
pub enum TCPState {
    Closed,
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

use TCPState::*;

#[derive(Clone)]
pub struct Socket {
    src_sock: SocketAddrV4,
    dst_sock: SocketAddrV4,
    tcp_state: TCPState,
    seg: SegmentVariables,
    snd: SendSequence,
    rcv: RecvSequence,
    // send_buffer (TODO: what size?)
    // recv_buffer (TODO: what size?)
    // retransmit_queue (TODO: which data structure?)
    // current_segment (TODO: what needs to be represented?)
}

impl Socket {
    pub fn new(src_sock: SocketAddrV4, dst_sock: SocketAddrV4, tcp_state: TCPState) -> Socket {
        Socket {
            src_sock,
            dst_sock,
            tcp_state,
            seg: SegmentVariables::new(),
            snd: SendSequence::new(),
            rcv: RecvSequence::new(),
        }
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
    pub nxt: u16,
    pub wnd: u16,
    pub up: u16,
    pub irs: u16,
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

// #[derive(Clone)]
// pub enum TCPTransition {
// PassiveOpen,
// ActiveOpen,
// RcvSyn,
// RcvSynAck,
// RcvAck,
// }

// use TCPTransition::*;

// pub const transitions: HashMap<(TCPState, TCPTransition), TCPState> = [
// ((Closed, PassiveOpen), Listen),
// ((Closed, ActiveOpen), SynSent),
// ]
// .iter()
// .cloned()
// .collect();

// impl TCPState {
// pub fn tcp_transition(state: TCPState, transition: TCPTransition) -> TCPState {
// match state {
// Closed => match transition {
// PassiveOpen => Listen,
// ActiveOpen => SynSent,
// _ => Closed,
// },
// Listen => match transition {
// RcvSyn => SynRcvd,
// _ => Listen,
// },
// SynSent => match transition {
// RcvSynAck => Established,
// _ => SynSent,
// },
// SynRcvd => match transition {
// RcvAck => Established,
// _ => SynRcvd,
// },
// _ => state,
// }
// }
// }
