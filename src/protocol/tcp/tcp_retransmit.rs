use dashmap::DashSet;

use std::{collections::HashSet, thread, time::Instant};

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
            let mut to_delete = HashSet::new();
            // iterate pending_socks
            for sock_entry in pending_socks.iter() {
                let sock_entry = sock_entry.key().clone();

                let sock = sockets.get_socket_by_entry(&sock_entry).unwrap();

                // clear all packets that have been acknowledged already
                sock.clear_retransmissions();

                let rtx_q = sock.rtx_q.clone();
                let mut rtx_q = rtx_q.lock().unwrap();

                // if no more to retransmit, remove from pending
                if rtx_q.is_empty() {
                    to_delete.insert(sock_entry);
                    continue;
                }

                match sock.get_tcp_state() {
                    TCPState::SynSent | TCPState::SynRcvd => {
                        // first packet should be SYN; if not, just drop
                        let rtx_seg = rtx_q.pop_front().unwrap();
                        if rtx_seg.segment.header.syn {
                            // if counter exceeds 2, add to delete and delete from sockets
                            if rtx_seg.counter > 2 {
                                to_delete.insert(sock_entry.clone());
                                sockets.delete_socket_by_entry(&sock_entry);
                            } else {
                                // check if timer exceeds 2^(counter)
                                let timeout =
                                    Duration::from_secs(2_u64.pow(rtx_seg.counter as u32));
                                if timeout <= rtx_seg.send_time.elapsed() {
                                    // if time elapsed > timeout, retransmit
                                    if sock
                                        .send(rtx_seg.segment, true, rtx_seg.counter + 1)
                                        .is_ok()
                                    {}
                                }
                            }
                        }
                    }
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

// pub fn check_data_retransmission(sock: Socket) {
// let mut rtx_q = sock.rtx_q;
// let snd = sock.snd.lock().unwrap();
// if rtx_q.is_empty() {
// return;
// }

// // pop the queue
// while rtx_q.front().unwrap().segment.header.sequence_number < snd.una {
// rtx_q.pop();
// }
// }
