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
                let sock = sockets.get_socket_by_entry(&sock_entry).unwrap();

                match sock.get_tcp_state() {
                    TCPState::SynSent => (),
                    TCPState::SynRcvd => (),
                    TCPState::Established
                    | TCPState::FinWait1
                    | TCPState::CloseWait
                    | TCPState::Closing => check_data_retransmission(sock),
                    TCPState::TimeWait => (),
                    TCPState::LastAck => (),
                    _ => (),
                }
            }

            thread::sleep(Duration::from_millis(1));
        }
    })
}

pub fn check_data_retransmission(sock: Socket) {
    let mut rtx_q = sock.rtx_q;
    let snd = sock.snd.lock().unwrap();
    if rtx_q.is_empty() {
        return;
    }

    // pop the queue
    while rtx_q.front().unwrap().segment.header.sequence_number < snd.una {
        rtx_q.pop();
    }
}
