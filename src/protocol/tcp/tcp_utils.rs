use dashmap::DashSet;

use std::thread;

use crate::protocol::{
    network::{ip_packet::*, InternetModule},
    tcp::{tcp_socket::*, *},
};

// pub const N_THREADS: usize = 4;
pub const CHAN_BOUND: usize = 1024; // TODO: find better bound

pub const WIN_SZ: u16 = u16::MAX;

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

pub fn make_accept_loop(
    accept_rx: Receiver<IPPacket>,
    send_tx: SyncSender<IPPacket>,
    socket_table: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
    listen_queue: Arc<DashMap<SocketEntry, ConcurrentQueue<SocketID>>>,
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

            println!("[accept_loop] requested sock entry: {:#?}", sock_entry);

            // check that socket entry for listener exists
            let socket = match socket_table.get_socket_by_entry(&sock_entry) {
                Some(socket) => socket,
                // if socket entry doesn't exist, check if 0.0.0.0:PORT exists
                None => {
                    sock_entry.src_sock = SocketAddrV4::new(0.into(), sock_entry.src_sock.port());
                    match socket_table.get_socket_by_entry(&sock_entry) {
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
            rcv.nxt = seq + 1;
            rcv.irs = seq;
            snd.nxt = iss + 1;
            snd.una = iss;

            // get new socket entry and ID, and increment ID
            let new_sock_entry = SocketEntry { src_sock, dst_sock };
            let new_id = next_id.fetch_add(1, Ordering::Relaxed);
            // insert into socket table
            socket_table.insert_entry(new_id, new_sock_entry.clone(), new_sock.clone());

            // insert into pending sockets
            pending_socks.insert(new_sock_entry);
            // insert into queue of potential bois to accept from this listener
            match listen_queue.get_mut(&sock_entry) {
                Some(mut cq) => cq.value_mut().push(new_id),
                None => {
                    // make one if non-existent
                    let mut concurrent_queue = ConcurrentQueue::new();
                    concurrent_queue.push(new_id);
                    listen_queue.insert(sock_entry, concurrent_queue);
                }
            }

            // send SYN+ACK
            if new_sock.send_syn_ack(snd.iss, rcv.nxt).is_ok() {}
        }

        eprintln!("accept loop terminated.");
    })
}

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
                rcv.nxt = seq_no + 1;
                rcv.irs = seq_no;
                if ack {
                    snd.una = ack_no;
                    // TODO: remove relevant sections on retransmission queue
                }

                // we've already verified ACK here, so just check if sync-SYN or SYN-ACK
                let sync = snd.una == snd.iss;
                // if synchronous SYN, set to SYN-RECEIVED; otherwise, ESTABLISHED
                *tcp_state = if sync {
                    // insert into pending sockets; we're waiting for an ACK
                    pending_socks.insert(sock_entry.clone());
                    TCPState::SynRcvd
                } else {
                    println!("[segment_loop] received SYN+ACK! establishing connection...");
                    // remove from pending sockets; we just got an ACK
                    pending_socks.remove(&sock_entry);
                    TCPState::Established
                };

                let sid = sockets.get_socket_id(&sock_entry).unwrap();
                sockets.insert_entry(sid, sock_entry, sock.clone());

                // send SYN+ACK/ACK to other end
                if sock.send_ack(sync, snd.una, snd.nxt, rcv.nxt).is_ok() {}
            } else {
                //// otherwise, check acceptability of segment:
                // - if rcv window = 0 and not an initial SYN
                // - if rcv window > 0 and SYN not in window
                // - if rcv window = 0 and has data
                // - if rcv window > 0 and neither start nor end in window
                if (seg_len == 0 && rcv.wnd == 0 && seq_no != rcv.nxt)
                    || (seg_len == 0 && rcv.wnd > 0 && !in_rcv_window(&sock, seq_no))
                    || (seg_len > 0 && rcv.wnd == 0)
                    || (seg_len > 0
                        && rcv.wnd > 0
                        && !in_rcv_window(&sock, seq_no)
                        && !in_rcv_window(&sock, seq_no + seg_len))
                {
                    eprintln!("[segment_loop] unacceptable segment; dropping...");
                    // if any of those conditions fail, then not acceptable, so send ACK
                    if sock.send_ack(false, snd.una, snd.nxt, rcv.nxt).is_ok() {}
                    // drop packet
                    continue;
                }

                // if SYN packet:
                if syn {
                    // if packet in window, error, so drop
                    if in_rcv_window(&sock, seq_no) {
                        eprintln!("[segment_loop] SYN in RCV window illegal, dropping...");

                        // TODO: cleanup:
                        // - flush all queues
                        // - send user an unsolicited "connection reset" signal
                        // - enter closed state, i.e. delete Socket
                        sockets.delete_socket_by_entry(&sock_entry);
                    }
                    // seqno checking handles when syn outside of rcv window
                    // if not ACK, we just drop, so only handle ACK case
                } else if ack {
                    // if in SYN_RCVD state...
                    if *tcp_state == TCPState::SynRcvd {
                        // and ACK in SND window, move to ESTABLISHED
                        if snd.una <= ack_no && ack_no <= snd.nxt {
                            *tcp_state = TCPState::Established;

                            // remove from pending queue
                            pending_socks.remove(&sock_entry);

                            // TODO: additional processing of data
                        }
                        // if outside window, drop segment
                    } else if *tcp_state == TCPState::Established {
                        // processing...
                    }
                }
            }
        }

        eprintln!("segment loop terminated.");
    })
}

/**
 * Construct TCP handler.
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

        // get socket entry of destination's socket
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
            // TODO: should we offload to (threadpooled) segment_tx, or just do checks here?
        } else if pending_socks.contains(&sock_entry) {
            let ackno = tcp_seg.header.acknowledgment_number;
            // ensure that ACKNO is in correct spot; if so, send to segment_loop
            if snd.una <= ackno && ackno <= snd.nxt && segment_tx.send(packet).is_ok() {}
        } else {
            // other stuff TODO: like whatttt
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

pub fn in_rcv_window(sock: &Socket, seq_no: u32) -> bool {
    let rcv = sock.rcv.lock().unwrap();
    rcv.nxt <= seq_no && seq_no < rcv.nxt + rcv.wnd as u32
}
