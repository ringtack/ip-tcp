use dashmap::DashSet;

use std::{thread, time::Instant};

use crate::protocol::{
    network::{ip_packet::*, InternetModule},
    tcp::{tcp_socket::*, *},
};

// pub const N_THREADS: usize = 4;
pub const CHAN_BOUND: usize = 1024; // TODO: find better bound

pub fn make_send_loop(
    send_rx: Receiver<IPPacket>, // TODO: other parameters
    ip_module: InternetModule,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // infinitely forward packets to IP module until TCP module closes
        for packet in send_rx {
            // send through IP module
            if let Err(e) = ip_module.send_ip(packet) {
                eprintln!("[make_send_loop] ip_module.send_ip failed: {}", e);
            }
        }

        eprintln!("send loop closed")
    })
}

/**
 * Handles accepting incoming connections to a listener socket.
 *
 * Inputs:
 * - accept_rx: receiver of incoming SYN segments.
 * - send_tx: sender for the TCP Module (i.e., where outgoing segments should be sent)
 * - sockets: copy of socket table (Arc not needed, since everything within is synchronized)
 * - pending_socks: set of all sockets with pending operations (i.e., waiting ACKs)
 * - listen_queue: map from listener sockets to a queue of sockets to be accepted
 * - next_id: synchronized counter for the next socket ID
 *
 * Returns:
 * - handle to which to join (for cleanup)
 */
pub fn make_accept_loop(
    accept_rx: Receiver<IPPacket>,
    send_tx: SyncSender<IPPacket>,
    sockets: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
    listen_queue: Arc<DashMap<SocketEntry, SynchronizedQueue<SocketID>>>,
    next_id: Arc<AtomicU8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // infinitely accept SYN packets until TCP module closes
        for packet in accept_rx {
            // destructure packet into Ipv4Header and TCPSegment
            let ip_hdr = packet.header;
            let syn_seg = match TCPSegment::from_bytes(packet.payload.as_slice()) {
                Ok(syn) => {
                    // verify that is actually SYN segment
                    if syn.header.syn {
                        syn
                    } else {
                        eprintln!("[accept_loop] incoming segment not SYN.");
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!("[accept_loop] failed to convert to bytes: {}", e);
                    continue;
                }
            };

            // get socket entry of destination's socket
            let mut sock_entry = get_socket_entry_in(&ip_hdr, &syn_seg.header);
            let dst_sock = sock_entry.dst_sock;

            let zero_sock = SocketAddrV4::new(0.into(), 0);
            // update to reflect passive listener's socket entry
            sock_entry.dst_sock = zero_sock;

            // println!("[accept_loop] requested sock entry: {:#?}", sock_entry);
            // check that socket entry for listener exists
            let socket = match sockets.get_socket_by_entry(&sock_entry) {
                Some(socket) => socket,
                // if socket entry doesn't exist, check if 0.0.0.0:PORT exists
                None => {
                    sock_entry.src_sock = SocketAddrV4::new(0.into(), sock_entry.src_sock.port());
                    match sockets.get_socket_by_entry(&sock_entry) {
                        Some(socket) => socket,
                        None => continue,
                    }
                }
            };

            let tcp_state = socket.tcp_state.lock().unwrap();
            // assert that "Passive OPEN" socket in Listen state
            if *tcp_state != TCPState::Listen {
                continue;
            }

            // get new socket information:
            // - on our end:
            //   - get intended source address (i.e. same as listener)
            //   - generate new port
            // - on other end:
            //   - use same as they specified
            let src_addr = ip_hdr.destination.into();
            let src_port = syn_seg.header.destination_port; //find_valid_port(&dst_sock, src_addr, &socket_table);
            let src_sock = SocketAddrV4::new(src_addr, src_port);

            println!(
                "[accept_loop] Received SYN from {}; opening socket on {}...",
                dst_sock, src_sock
            );

            // make new socket
            let new_sock = Socket::new(src_sock, dst_sock, TCPState::SynRcvd, send_tx.clone());
            // - Select ISS [TODO: currently just 0]
            let iss = 0;
            let seq = syn_seg.header.sequence_number;
            // update socket's values:
            let (mut snd, mut rcv) = (new_sock.snd.lock().unwrap(), new_sock.rcv.lock().unwrap());
            snd.set_iss(iss);
            rcv.set_irs(seq);

            // get new socket entry and ID, and increment ID
            let new_sock_entry = SocketEntry { src_sock, dst_sock };
            let new_id = next_id.fetch_add(1, Ordering::Relaxed);
            // insert into socket table
            sockets.insert_entry(new_id, new_sock_entry.clone(), new_sock.clone());

            // insert into pending sockets
            pending_socks.insert(new_sock_entry);
            // insert into queue of potential bois to accept from this listener
            match listen_queue.get_mut(&sock_entry) {
                Some(mut cq) => cq.value_mut().push(new_id),
                None => {
                    // make one if non-existent
                    let mut synchronized_queue = SynchronizedQueue::new();
                    synchronized_queue.push(new_id);
                    listen_queue.insert(sock_entry, synchronized_queue);
                }
            }

            // send SYN+ACK
            if new_sock.send_syn_ack(snd.iss, rcv.nxt, rcv.wnd).is_ok() {}
        }

        eprintln!("accept loop terminated.");
    })
}

/**
 * Handles incoming segments of all kinds! (i.e., everything except accepting/closing connections).
 *
 * Inputs:
 * - segment_rx: receiver of incoming segments.
 * - sockets: copy of socket table
 * - pending_socks: set of all sockets with pending operation
 *
 * Returns:
 * - handle to which to join (for cleanup)
 */
pub fn make_segment_loop(
    segment_rx: Receiver<IPPacket>,
    sockets: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for packet in segment_rx {
            // destructure packet into Ipv4Header and TCPSegment
            let ip_hdr = packet.header;
            let tcp_seg = match TCPSegment::from_bytes(packet.payload.as_slice()) {
                Ok(seg) => seg,
                Err(e) => {
                    eprintln!("[accept_loop] failed to convert to bytes: {}", e);
                    continue;
                }
            };
            // get relevant header fields
            let syn = tcp_seg.header.syn;
            let seq_no = tcp_seg.header.sequence_number;
            let ack = tcp_seg.header.ack;
            let ack_no = tcp_seg.header.acknowledgment_number;
            let seg_wnd = tcp_seg.header.window_size;
            let seg_len = tcp_seg.data.len() as u32;

            // get socket entry of destination's socket
            let sock_entry = get_socket_entry_in(&ip_hdr, &tcp_seg.header);

            // get actual sock
            let sock = sockets.get_socket_by_entry(&sock_entry).unwrap();

            let mut tcp_state = sock.tcp_state.lock().unwrap();
            let (mut snd, mut rcv) = (sock.snd.lock().unwrap(), sock.rcv.lock().unwrap());
            // if SYN_SENT:
            if *tcp_state == TCPState::SynSent {
                // if not SYN, drop segment
                if !syn {
                    continue;
                }

                // update send/receive sequence values
                rcv.set_irs(seq_no);
                if ack {
                    snd.set_una(seq_no, ack_no, seg_wnd);
                }
                // TODO: remove relevant sections on retransmission queue

                // If we've received SYN+ACK, so send SYN back and mark established
                if ack {
                    println!(
                        "[{}] received SYN+ACK! establishing connection to {}.",
                        sock.src_sock, sock.dst_sock
                    );
                    // remove from pending sockets; we just got an ACK
                    pending_socks.remove(&sock_entry);
                    *tcp_state = TCPState::Established;

                    // send ACK back
                    if sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).is_ok() {}
                    // otherwise (simultaneous SYN), set to SYN-RECEIVED and send SYN-ACK back
                } else {
                    // insert into pending sockets; we're waiting for an ACK
                    pending_socks.insert(sock_entry.clone());
                    *tcp_state = TCPState::SynRcvd;

                    print!("!!!SYNC!!! ");
                    // send SYN+ACK back
                    if sock.send_syn_ack(snd.una, rcv.nxt, rcv.wnd).is_ok() {}
                }

                // [NB: I structured it like this to prevent giga indents]
                continue;
            }

            // check acceptability of segment
            if !rcv.acceptable_seg(seq_no, seg_len) {
                eprintln!("[segment_loop] unacceptable segment; dropping...");
                // if any of those conditions fail, then not acceptable, so send ACK back
                if sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).is_ok() {}
                // drop packet
                continue;
            }

            // if SYN packet:
            if syn {
                // if packet in window, error, so drop
                if rcv.in_window(seq_no) {
                    eprintln!("[segment_loop] SYN in RCV window illegal, dropping...");

                    // TODO: cleanup:
                    // - flush all queues
                    // - send user an unsolicited "connection reset" signal
                    // - enter closed state, i.e. delete Socket
                    sockets.delete_socket_by_entry(&sock_entry);
                } // else { drop } -> seqno checking handles when syn outside of rcv window
                continue;
            } else if !ack {
                // [NB: I structured it like this to prevent giga indents]
                continue; // if not ACK, we just drop, so only handle ACK case
            }

            // if in SYN_RCVD state...
            if *tcp_state == TCPState::SynRcvd {
                // and ACK in SND window, move to ESTABLISHED
                if snd.in_una_window(ack_no) {
                    // update UNA & co. values
                    snd.set_una(seq_no, ack_no, seg_wnd);

                    println!(
                        "[{}] Established connection to {}",
                        sock.src_sock, sock.dst_sock
                    );
                    *tcp_state = TCPState::Established;

                    // remove from pending queue
                    pending_socks.remove(&sock_entry);

                    // TODO: additional processing of data
                    // ...
                } // else { drop } -> if outside window, drop segment
            } else if *tcp_state == TCPState::Established {
                let old_una = snd.una;
                // if ACK in [SND.UNA ... SND.UNA + SND.NXT], update send window
                if snd.in_una_window(ack_no) {
                    snd.wnd = seg_wnd;
                }

                // if ACK in (SND.UNA ... SND.UNA + SND.NXT], update send variables
                if ack_no != old_una && snd.in_una_window(ack_no) {
                    snd.set_una(seq_no, ack_no, seg_wnd);
                }

                // if WND == 0, add to pending_socks for zero probing
                // if seg_wnd == 0 {
                // let mut timer = sock.timer.lock().unwrap();
                // *timer = Instant::now();
                // pending_socks.insert(sock_entry);
                // }

                // if has data:
                if !tcp_seg.data.is_empty() {
                    // fill up receive buffer [TODO: error handle]
                    if let Err(e) = rcv.write(tcp_seg.data.as_slice(), seq_no) {
                        eprintln!("[segment_loop] {}", e);
                    } else if sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).is_ok() {
                    }
                }
            }
        }

        eprintln!("segment loop terminated.");
    })
}

/**
 * Handles shutdown requests.
 */
pub fn make_shutdown_handler() -> thread::JoinHandle<()> {
    // TODO: handle shutdowns
    thread::spawn(|| {
        //
    })
}

/**
 * Handles pending socket requests.
 */
// pub fn make_pending_sock_handler(
// sockets: SocketTable,
// pending_socks: Arc<DashSet<SocketEntry>>,
// ) -> thread::JoinHandle<()> {
// }

/**
 * Construct TCP handler.
 *
 * Inputs:
 * - sockets: copy of socket table
 * - pending_socks: set of all sockets with pending operation
 * - accept_tx: Sender for the accept_loop
 * - segment_tx: Sender for the segment_loop
 *
 * Returns:
 * - handler!
 */
pub fn make_tcp_handler(
    sockets: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
    accept_tx: Sender<IPPacket>,
    segment_tx: Sender<IPPacket>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        // destructure packet into Ipv4Header and TCPSegment
        let ip_hdr = packet.header;
        let tcp_seg = match TCPSegment::from_bytes(packet.payload.as_slice()) {
            Ok(seg) => seg,
            Err(e) => {
                eprintln!("[tcp_handler] failed to convert to bytes: {}", e);
                return Err(Error::new(ErrorKind::InvalidData, "invalid data"));
            }
        };

        // verify checksum; if incorrect, drop packet
        if let Ok(checksum) = tcp_seg.header.calc_checksum_ipv4(&ip_hdr, &tcp_seg.data) {
            if tcp_seg.header.checksum != checksum {
                eprintln!("Incorrect checksum for packet.");
                return Ok(());
            }
        } else {
            eprintln!("Packet incorrectly formatted; cannot compute checksum.");
            return Ok(());
        }

        //// TCP Handler does verification that socket exists. In the other handlers (accept,
        //segment), we can unwrap the socket from the socket entry.
        let sock_entry = get_socket_entry_in(&ip_hdr, &tcp_seg.header);
        let found_sock_entry = match find_sock_entry(&sock_entry, &sockets) {
            Some(fse) => fse,
            None => {
                eprintln!("[tcp_handler] destination does not exist.");
                return Ok(());
            }
        };

        // get socket itself
        let sock = match sockets.get_socket_by_entry(&found_sock_entry) {
            Some(sock) => sock,
            None => {
                eprintln!("[tcp_handler] destination does not exist.");
                return Ok(());
            }
        };

        // repackage IPPacket, since we'll need to forward
        let packet = IPPacket {
            header: ip_hdr,
            payload: tcp_seg.to_bytes()?,
        };
        //// Forward, based on TCP State:
        let syn = tcp_seg.header.syn;
        let ack = tcp_seg.header.ack;
        let fin = tcp_seg.header.fin;

        let tcp_state = sock.tcp_state.lock().unwrap();
        let (snd, _) = (sock.snd.lock().unwrap(), sock.rcv.lock().unwrap());
        // If LISTEN, forward to accept_loop only if SYN packet
        if *tcp_state == TCPState::Listen {
            if ack {
                return Err(Error::new(ErrorKind::ConnectionRefused, "no ACK listen!"));
            } else if syn {
                if accept_tx.send(packet).is_ok() {}
            } else {
                println!("[tcp_handler] TODO: more informative error message");
            }
            // if in pending_socks, socket is in SYN_SENT/SYN_RCVD state
        } else if pending_socks.contains(&sock_entry) {
            // TODO: should we offload to segment_loop, or just do checks here?
            let ackno = tcp_seg.header.acknowledgment_number;
            // ensure that ACKNO is in correct spot; if so, send to segment_loop
            if snd.una <= ackno && ackno <= snd.nxt && segment_tx.send(packet).is_ok() {}
            // if Established, should be able to receive segments
        } else if *tcp_state == TCPState::Established {
            // other stuff TODO: like whatttt
            if segment_tx.send(packet).is_ok() {}
        }

        Ok(())
    }))
}

/**
 * Helper function to get a socket entry from a given IP/TCP Header of an incoming packet.
 */
pub fn get_socket_entry_in(ip_hdr: &Ipv4Header, tcp_hdr: &TcpHeader) -> SocketEntry {
    // TODO: check order, make less scuffed
    let src_sock = SocketAddrV4::new(ip_hdr.destination.into(), tcp_hdr.destination_port);
    let dst_sock = SocketAddrV4::new(ip_hdr.source.into(), tcp_hdr.source_port);
    SocketEntry { src_sock, dst_sock }
}

/**
 * Helper function to get a socket entry from a given IP/TCP Header of an outgoing packet.
 */
pub fn get_socket_entry_out(ip_hdr: &Ipv4Header, tcp_hdr: &TcpHeader) -> SocketEntry {
    // TODO: check order, make less scuffed
    let src_sock = SocketAddrV4::new(ip_hdr.source.into(), tcp_hdr.source_port);
    let dst_sock = SocketAddrV4::new(ip_hdr.destination.into(), tcp_hdr.destination_port);
    SocketEntry { src_sock, dst_sock }
}

/**
 * Finds the next valid port. [TODO: make much better LMAO]
 */
pub fn find_valid_port(dst_sock: &SocketAddrV4, src_addr: Ipv4Addr, st: &SocketTable) -> u16 {
    let mut port = 10000;
    let mut sock_entry = SocketEntry {
        src_sock: SocketAddrV4::new(src_addr, port),
        dst_sock: *dst_sock,
    };
    while st.has_entry(&sock_entry) {
        port += 1;
        sock_entry.src_sock = SocketAddrV4::new(src_addr, port);
    }

    port
}

/**
 * Attempts to find the socket associated with the specified sock_entry. In order of searching:
 * - sock_entry
 * - sock_entry, with 0s set as dst_sock
 * - sock_entry, with 0s set as dst_sock and 0 set as src_addr
 *
 * Inputs:
 * - sock_entry: the incoming socket entry request
 *
 * Returns:
 * - the original socket entry, or None if none of the above
 */
pub fn find_sock_entry(sock_entry: &SocketEntry, st: &SocketTable) -> Option<SocketEntry> {
    if st.has_entry(sock_entry) {
        Some(sock_entry.clone())
    } else {
        let mut zero_sock = SocketEntry {
            src_sock: sock_entry.src_sock,
            dst_sock: SocketAddrV4::new(0.into(), 0),
        };
        if st.has_entry(&zero_sock) {
            Some(zero_sock)
        } else {
            zero_sock.src_sock = SocketAddrV4::new(0.into(), zero_sock.src_sock.port());
            if st.has_entry(&zero_sock) {
                Some(zero_sock)
            } else {
                None
            }
        }
    }
}
