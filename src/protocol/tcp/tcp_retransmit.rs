use dashmap::DashSet;

use std::{
    cmp::{max, min},
    collections::HashSet,
    thread,
    time::Duration,
};

use crate::protocol::tcp::{tcp_socket::*, *};

pub enum RtxState {
    MaxRetransmissions,
    FullyAcked,
    Pending,
    Expired,
}

const SYN_RETRANSMIT_LIMIT: usize = 3;
const DATA_RETRANSMIT_LIMIT: usize = 20;
const ZP_RETRANSMIT_LIMIT: usize = 20;

const MAX_EXP_TIME: u64 = 1200; // in MS
const RTX_SLEEP_TIME: u64 = 5000; // in microseconds

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
    thread::spawn(move || loop {
        let mut to_delete = HashSet::new();
        // iterate pending_socks
        for sock_entry in pending_socks.iter() {
            let sock_entry = sock_entry.key().clone();
            let sock = match sockets.get_socket_by_entry(&sock_entry) {
                Some(s) => s,
                None => {
                    to_delete.insert(sock_entry);
                    continue;
                }
            };

            match sock.get_tcp_state() {
                TCPState::SynSent | TCPState::SynRcvd => match check_syn_retransmissions(&sock) {
                    RtxState::FullyAcked => {
                        // println!(
                        // "{}:{} fully established connection!",
                        // *sock.src_sock.ip(),
                        // sock.src_sock.port()
                        // );
                        to_delete.insert(sock_entry.clone());
                    }
                    RtxState::MaxRetransmissions => {
                        println!(
                                    "{}:{} failed to send data after {} re-transmissions. Closing socket...",
                                    *sock.src_sock.ip(),
                                    sock.src_sock.port(),
                                    SYN_RETRANSMIT_LIMIT
                                );
                        to_delete.insert(sock_entry.clone());
                        sockets.delete_socket_by_entry(&sock_entry);
                    }
                    _ => (),
                },
                TCPState::Established
                | TCPState::FinWait1
                | TCPState::CloseWait
                | TCPState::Closing
                | TCPState::LastAck => {
                    if let RtxState::Expired = check_timewait_expiration(&sock) {
                        println!(
                            "{}:{} has waited over {}s (2 * MSL). Closing socket...",
                            *sock.src_sock.ip(),
                            sock.src_sock.port(),
                            2 * MSL,
                        );
                        to_delete.insert(sock_entry.clone());
                        sockets.delete_socket_by_entry(&sock_entry);
                        continue;
                    }
                    let rtx_state = if sock.is_zero_probing() {
                        zero_probe_retransmission(&sock)
                    } else {
                        check_data_retransmission(&sock)
                    };
                    // handle state after transmitting
                    match rtx_state {
                        RtxState::FullyAcked => {
                            println!(
                                "{}:{} is fully acknowledged!",
                                *sock.src_sock.ip(),
                                sock.src_sock.port()
                            );
                            to_delete.insert(sock_entry.clone());
                            // notify CV, might be waiting
                        }
                        RtxState::MaxRetransmissions => {
                            println!(
                                    "{}:{} failed to establish connection after {} re-transmissions. Closing socket...",
                                    *sock.src_sock.ip(),
                                    sock.src_sock.port(),
                                    DATA_RETRANSMIT_LIMIT
                                );
                            to_delete.insert(sock_entry.clone());
                            sockets.delete_socket_by_entry(&sock_entry);
                        }
                        _ => (),
                    }
                }
                TCPState::TimeWait => {
                    if let RtxState::Expired = check_timewait_expiration(&sock) {
                        println!(
                            "{}:{} has waited over {}s (2 * MSL). Closing socket...",
                            *sock.src_sock.ip(),
                            sock.src_sock.port(),
                            2 * MSL,
                        );
                        to_delete.insert(sock_entry.clone());
                        sockets.delete_socket_by_entry(&sock_entry);
                    }
                }
                _ => (),
            }
        }

        // remove all the bois that are done
        for sock_entry in to_delete {
            pending_socks.remove(&sock_entry);
        }

        thread::sleep(Duration::from_micros(RTX_SLEEP_TIME));
    })
}

/**
 * Handler to check SYN segment retransmissions. If true, socket is done (so delete!).
 *
 * Returns:
 * - State of socket retransmission (FullyAcked if SYN acknowledged, MaxRetransmissions if exceeded
 * max SYN retransmissions, and Pending if in the process)
 */
pub fn check_syn_retransmissions(sock: &Socket) -> RtxState {
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
            // check if timer exceeds 2^(counter)[s]
            let timeout = Duration::from_secs(2_u64.pow(rtx_seg.counter as u32));
            if rtx_seg.send_time.elapsed() > timeout {
                println!("SYN timed out; retransmitting");
                sock.send(rtx_seg.segment, true, rtx_seg.counter + 1).ok();
            } else {
                // println!("still pending");
                // otherwise, re-add to queue
                sock.rtx_q_push(rtx_seg)
            }
        }
    }
    RtxState::Pending
}

/**
 * Handler to calculate zero probing retransmissions.
 *
 * Returns:
 * - State of socket retarnsmission (FullyAcked if all data acknowledged, MaxRetransmissions if
 * exceeded max data/zero-probe retransmissions, Pending if in the process)
 */
pub fn zero_probe_retransmission(sock: &Socket) -> RtxState {
    // if not zero probing anymore, fully acked
    let zp_time = match *sock.zero_probe.lock().unwrap() {
        Some(zp_time) => zp_time,
        None => {
            // println!("no longer zp");
            return RtxState::FullyAcked;
        }
    };

    // clear rtx_q; if empty, fully acked
    sock.clear_retransmissions();
    if sock.rtx_q_empty() {
        // println!("rtx_q cleared");
        return RtxState::FullyAcked;
    }

    let (counter, timeout) = sock.get_zp_counters();
    // if at limit, indicate exceed retransmissions
    if timeout as usize >= ZP_RETRANSMIT_LIMIT {
        return RtxState::MaxRetransmissions;
    }

    // get maximum timer to use
    let counter = max(counter, timeout) as usize;
    let mut segment = sock.rtx_q_pop().unwrap();
    // manually set counter and time sent... this is so janky
    segment.counter = counter;
    segment.send_time = zp_time;

    // if not timeout, just reappend
    if !is_segment_timeout(&segment, &sock.get_rto()) {
        sock.rtx_q_push_front(segment);
    } else {
        // otherwise, need to retransmit data, with increased timeout counter
        // println!("retransmissing");
        sock.inc_timeout_counter();

        // atp segment's counter is just dummy value lol
        sock.send(segment.segment, true, 0).ok();
    }

    RtxState::Pending
}

/**
 * Handler to check data segment retransmissions.
 *
 * Returns:
 * - State of socket retransmission (FullyAcked if all data acknowledged, MaxRetransmissions if
 * exceeded max data retransmissions, and Pending if in the process)
 */
pub fn check_data_retransmission(sock: &Socket) -> RtxState {
    // pop the ACK'ed segments from queue
    sock.clear_retransmissions();
    // all segments are ACK'ed
    if sock.rtx_q_empty() {
        return RtxState::FullyAcked;
    }

    // retransmit all segments that are timed out
    while !sock.rtx_q_empty() {
        let segment = sock.rtx_q_pop().unwrap();
        if !is_segment_timeout(&segment, &sock.get_rto()) {
            sock.rtx_q_push_front(segment);
            break;
        }

        // if at limit, we close the socket and return true
        if segment.counter >= DATA_RETRANSMIT_LIMIT {
            return RtxState::MaxRetransmissions;
        }

        // println!("retransmitting data");

        // otherwise, retransmit with increased counter
        sock.send(segment.segment, true, segment.counter + 1).ok();
    }
    RtxState::Pending
}

/**
 * Handler to check if TimeWait expired.
 */
pub fn check_timewait_expiration(sock: &Socket) -> RtxState {
    // if socket's TimeWait has been over 2*MSL, return Expired; otherwise, indicate Pending
    let expiration = 2 * Duration::from_secs(MSL);
    match sock.get_time_wait() {
        Some(tw) => {
            if tw.elapsed() > expiration {
                RtxState::Expired
            } else {
                RtxState::Pending
            }
        }
        // in this case, normal socket (i.e. Established/CloseWait in normal sending)
        None => RtxState::Pending,
    }
}

/**
 * Checks if a segment has timed out, given an RTO. Exponential backoff based on segment's counter
 * will be computed.
 */
pub fn is_segment_timeout(segment: &SegmentEntry, rto: &Duration) -> bool {
    // from the RTO, compute exponential backoff time
    let rto = dur_exp_backoff(*rto, segment.counter);

    // println!("RTO: {:#?}", rto);

    segment.send_time.elapsed().ge(&rto)
}

/**
 * Computes the exponential backoff of a duration, capped at MAX_EXP_TIME[ms].
 *
 * Inputs:
 * - duration: duration to exponentially backoff
 * - counter: number of retransmission times
 *
 * Returns:
 * - exponentially backoff'd duration
 */
pub fn dur_exp_backoff(duration: Duration, counter: usize) -> Duration {
    min(
        Duration::from_millis(MAX_EXP_TIME),
        duration * 2_u32.pow(counter as u32),
    )
}
