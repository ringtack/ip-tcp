use dashmap::DashSet;

use std::{thread, time::Instant};

use crate::protocol::{
    network::{ip_packet::*, InternetModule},
    tcp::{tcp_socket::*, *},
};

/**
 * Handles all retransmissions
 *
 * Inputs:
 * - segment_rx: receiver of incoming segments.
 * - sockets: copy of socket table
 * - pending_socks: set of all sockets with pending operation
 *
 * Returns:
 * -
 */
pub fn check_retransmission(
    sockets: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            // iterate pending_socks
            for sock_entry in pending_socks.iter() {
                let sock = sockets.get_socket_by_entry(&sock_entry)?;
                match sock.get_tcp_state() {
                    TCPState::SynSent => (),
                    TCPState::SynRcvd => (),
                    TCPState::Established
                    | TCPState::FinWait1
                    | TCPState::CloseWait
                    | TCPState::Closing => (),
                    TCPState::TimeWait => (),
                    TCPState::LastAck => (),
                    _ => (),
                }
            }

            thread::sleep(Duration::from_millis(1));
        }
    })
}
