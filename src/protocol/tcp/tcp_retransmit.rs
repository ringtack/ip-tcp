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
    let mut rtx_q = sock.rtx_q.lock().unwrap();
    let snd = sock.snd.lock().unwrap();

    // pop the ACK'ed segments from queue
    while !rtx_q.is_empty()
        && rtx_q.front().unwrap().segment.header.sequence_number
            + rtx_q.front().unwrap().segment.header.size
            < snd.una
    {
        rtx_q.pop_front();
    }

    // all segments are ACK'ed
    if rtx_q.is_empty() {
        return;
    }

    // retransmit all segments that are timed out
    let mut to_delete = 0;
    for segment in rtx_q.iter() {
        if !is_segment_timeout(segment, &sock.get_rto()) {
            break;
        }
        sock.send(segment.segment.clone(), true, segment.counter + 1)
            .is_ok();
        to_delete += 1;
    }
    for _ in 0..to_delete {
        rtx_q.pop_front();
    }
}

pub fn is_segment_timeout(segment: &SegmentEntry, rto: &Duration) -> bool {
    segment.send_time.elapsed().ge(rto)
}
