use dashmap::DashSet;

use std::{collections::HashSet, thread, time::Instant};

use crate::protocol::{
    network::{ip_packet::*, InternetModule},
    tcp::{tcp_socket::*, *},
};

pub enum RtxState {
    MaxRetransmissions,
    FullyAcked,
    Pending,
}

const SYN_RETRANSMIT_LIMIT: usize = 3;
const DATA_RETRANSMIT_LIMIT: usize = 10;

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

                match sock.get_tcp_state() {
                    TCPState::SynSent | TCPState::SynRcvd => {
                        match check_syn_retransmissions(sock.clone()) {
                            RtxState::FullyAcked => {
                                println!(
                                    "{}:{} fully established connection!",
                                    *sock.src_sock.ip(),
                                    sock.src_sock.port()
                                );
                                to_delete.insert(sock_entry.clone());
                            }
                            RtxState::MaxRetransmissions => {
                                println!(
                                "{}:{} failed to establish connection after 3 re-transmissions. Closing socket...",
                                *sock.src_sock.ip(),
                                sock.src_sock.port()
                            );
                                to_delete.insert(sock_entry.clone());
                                sockets.delete_socket_by_entry(&sock_entry);
                            }
                            _ => (),
                        }
                    }
                    TCPState::Established
                    | TCPState::FinWait1
                    | TCPState::CloseWait
                    | TCPState::Closing => {
                        println!("hi");

                        //TODO, if zero probing
                        //else
                        match check_data_retransmission(sock.clone()) {
                            RtxState::FullyAcked => {
                                println!(
                                    "{}:{} is fully acknowledged!",
                                    *sock.src_sock.ip(),
                                    sock.src_sock.port()
                                );
                                to_delete.insert(sock_entry.clone());
                            }
                            RtxState::MaxRetransmissions => {
                                println!(
                                    "{}:{} failed to establish connection after 3 re-transmissions. Closing socket...",
                                    *sock.src_sock.ip(),
                                    sock.src_sock.port()
                                );
                                to_delete.insert(sock_entry.clone());
                                sockets.delete_socket_by_entry(&sock_entry);
                            }
                            _ => (),
                        }
                    }
                    TCPState::TimeWait => (),
                    TCPState::LastAck => (),
                    _ => (),
                }
            }

            // remove all the bois that are done
            for sock_entry in to_delete {
                pending_socks.remove(&sock_entry);
            }

            thread::sleep(Duration::from_millis(1000));
        }
    })
}

/**
 * Handler to check SYN segment retransmissions. If true, socket is done (so delete!).
 */
pub fn check_syn_retransmissions(sock: Socket) -> RtxState {
    // clear all packets that have been acknowledged already
    sock.clear_retransmissions();

    // if no more to retransmit, remove from pending
    if sock.rtx_q_empty() {
        return RtxState::FullyAcked;
    }

    // first packet should be SYN; if not, just drop
    let rtx_seg = sock.rtx_q_pop().unwrap();
    if rtx_seg.segment.header.syn {
        // if counter exceeds 3, add to delete and delete from sockets
        if rtx_seg.counter >= SYN_RETRANSMIT_LIMIT {
            return RtxState::MaxRetransmissions;
        } else {
            // check if timer exceeds 2^(counter)
            let timeout = Duration::from_secs(2_u64.pow(rtx_seg.counter as u32));
            if timeout <= rtx_seg.send_time.elapsed() {
                println!("timed out; retransmitting");

                // if time elapsed > timeout, retransmit
                if sock
                    .send(rtx_seg.segment, true, rtx_seg.counter + 1)
                    .is_ok()
                {}
            } else {
                // otherwise, re-add to queue
                sock.rtx_q_push(rtx_seg)
            }
        }
    }
    RtxState::Pending
}

pub fn check_data_retransmission(sock: Socket) -> RtxState {
    // pop the ACK'ed segments from queue
    sock.clear_retransmissions();
    // all segments are ACK'ed
    if sock.rtx_q_empty() {
        return RtxState::FullyAcked;
    }

    // retransmit all segments that are timed out
    while !sock.rtx_q_empty() {
        println!("hi");

        let segment = sock.rtx_q_pop().unwrap();
        if !is_segment_timeout(&segment, &sock.get_rto()) {
            println!("not timeout");

            sock.rtx_q_push_front(segment);
            break;
        }

        // if at limit, we close the socket and return true
        if segment.counter >= DATA_RETRANSMIT_LIMIT {
            return RtxState::MaxRetransmissions;
        }

        // retransmit
        if sock
            .send(segment.segment.clone(), true, segment.counter + 1)
            .is_ok()
        {}
    }
    // for segment in rtx_q.iter() {
    // if !is_segment_timeout(segment, &sock.get_rto()) {
    // break;
    // }
    // // if at limit, we close the socket by return true
    // if segment.counter >= RETRANSMIT_LIMIT {
    // return true;
    // }
    // // retransmit
    // if sock
    // .send(segment.segment.clone(), true, segment.counter + 1)
    // .is_ok()
    // {}
    // to_delete += 1;
    // }

    RtxState::Pending
}

pub fn is_segment_timeout(segment: &SegmentEntry, rto: &Duration) -> bool {
    segment.send_time.elapsed().ge(rto)
}
