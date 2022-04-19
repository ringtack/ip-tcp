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

#[derive(Clone)]
pub enum TCPTransition {
    PassiveOpen,
    ActiveOpen,
    RcvSyn,
    RcvSynAck,
    RcvAck,
}

use TCPState::*;
use TCPTransition::*;

// pub const transitions: HashMap<(TCPState, TCPTransition), TCPState> = [
// ((Closed, PassiveOpen), Listen),
// ((Closed, ActiveOpen), SynSent),
// ]
// .iter()
// .cloned()
// .collect();

impl TCPState {
    pub fn tcp_transition(state: TCPState, transition: TCPTransition) -> TCPState {
        match state {
            Closed => match transition {
                PassiveOpen => Listen,
                ActiveOpen => SynSent,
                _ => Closed,
            },
            Listen => match transition {
                RcvSyn => SynRcvd,
                _ => Listen,
            },
            SynSent => match transition {
                RcvSynAck => Established,
                _ => SynSent,
            },
            SynRcvd => match transition {
                RcvAck => Established,
                _ => SynRcvd,
            },
            _ => state,
        }
    }
}

#[derive(Clone)]
pub struct Socket {
    pub tcp_state: TCPState,
    ss: SendSequence,
    rs: RecvSequence,
    // rcv_buffer, send_buffer
    // Vec<u8>
}

impl Socket {
    pub fn new(tcp_state: TCPState) -> Socket {
        Socket {
            tcp_state,
            ss: SendSequence::new(),
            rs: RecvSequence::new(),
        }
    }
}

#[derive(Clone)]
pub struct SendSequence {
    pub una: u16,
    pub nxt: u16,
    pub wnd: u16,
    pub up: u16,
    pub wl1: u16,
    pub wl2: u16,
    pub iss: u16,
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
