use super::tcp_socket::TCPState;
use snafu::prelude::*;

use std::net::Ipv4Addr;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum TCPError {
    #[snafu(display("Message len {} exceeds max len {}!", msg_len, max_len))]
    MsgSize { msg_len: usize, max_len: usize },

    #[snafu(display(
        "[ENOBUFS] Not enough buffer space right now [msg_len: {}, remaining len: {}]",
        msg_len,
        remaining_len
    ))]
    NoBufs {
        msg_len: usize,
        remaining_len: usize,
    },

    #[snafu(display(
        "Requested more than available [count: {}, num_bytes: {}]",
        count,
        num_bytes
    ))]
    NoData { count: usize, num_bytes: usize },

    #[snafu(display("Invalid state [{}] for {} ", tcp_state, command))]
    InvalidState {
        tcp_state: TCPState,
        command: String,
    },

    #[snafu(display("[EBADF] {} not valid socket descriptor", sock_id))]
    BadFd { sock_id: u8 },

    #[snafu(display("{}", error))]
    InvalidArguments { error: String },

    #[snafu(display(
        "[EADDRINUSE] {}:{} already in use! (if port < 1024, reserved)",
        addr,
        port
    ))]
    AddrInUse { addr: Ipv4Addr, port: u16 },
}

pub type TCPResult<T, E = TCPError> = std::result::Result<T, E>;
