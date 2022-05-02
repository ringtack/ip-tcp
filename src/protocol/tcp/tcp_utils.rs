use dashmap::DashSet;

use std::thread;

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

            let tcp_state = socket.get_tcp_state();
            // assert that "Passive OPEN" socket in Listen state
            if tcp_state != TCPState::Listen {
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

            eprintln!(
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
            let fin = tcp_seg.header.fin;

            // get socket entry of destination's socket
            let sock_entry = get_socket_entry_in(&ip_hdr, &tcp_seg.header);

            // get actual sock
            let sock = sockets.get_socket_by_entry(&sock_entry).unwrap();

            let tcp_state = sock.get_tcp_state();
            let (mut snd, mut rcv) = (sock.snd.lock().unwrap(), sock.rcv.lock().unwrap());
            // if SYN_SENT:
            if tcp_state == TCPState::SynSent {
                // if not SYN, drop segment
                if !syn {
                    continue;
                }

                // update send/receive sequence values
                rcv.set_irs(seq_no);

                // If we've received SYN+ACK, so send SYN back and mark established
                if ack {
                    snd.set_una(seq_no, ack_no, seg_wnd);

                    eprintln!(
                        "[{}] received SYN+ACK! establishing connection to {}.",
                        sock.src_sock, sock.dst_sock
                    );
                    // update TCP state
                    sock.set_tcp_state(TCPState::Established);

                    // notify waiting CV
                    let (_, cv) = &*sock.pending.clone();
                    cv.notify_all();

                    // send ACK back
                    sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).ok();
                    // otherwise (simultaneous SYN), set to SYN-RECEIVED and send SYN-ACK back
                } else {
                    // update TCP state
                    sock.set_tcp_state(TCPState::SynRcvd);

                    print!("!!!SYNC!!! ");
                    // send SYN+ACK back
                    if sock.send_syn_ack(snd.una, rcv.nxt, rcv.wnd).is_ok() {}

                    // TODO: hopefully this fixes my deadlock
                    drop(snd);
                    drop(rcv);
                    // insert into pending sockets; we're waiting for an ACK
                    pending_socks.insert(sock_entry.clone());
                }

                // [NB: I structured it like this to prevent giga indents]
                continue;
            }

            // check acceptability of segment
            if !rcv.acceptable_seg(seq_no, seg_len) {
                // eprintln!("[segment_loop] unacceptable segment; dropping...");
                // if any of those conditions fail, then not acceptable, so send ACK back
                if sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).is_ok() {}
                // drop packet
                continue;
            }

            // if SYN packet:
            if syn {
                // if packet in window, error, so drop
                if rcv.in_window(seq_no) {
                    // eprintln!("[segment_loop] SYN in RCV window illegal, dropping...");

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
            if tcp_state == TCPState::SynRcvd {
                // and FIN and should be next, move to CloseWait
                if fin && rcv.nxt == seq_no {
                    sock.set_tcp_state(TCPState::CloseWait);
                    rcv.nxt += 1;
                    // send ACK back
                    if sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).is_ok() {}
                // otherwise, if ACK in SND window, move to ESTABLISHED
                } else if snd.in_una_nxt_window(ack_no) {
                    // update UNA & co. values
                    snd.set_una(seq_no, ack_no, seg_wnd);

                    eprintln!(
                        "[{}] Established connection to {}",
                        sock.src_sock, sock.dst_sock
                    );
                    sock.set_tcp_state(TCPState::Established);

                    // notify waiting CV
                    let (_, cv) = &*sock.pending.clone();
                    cv.notify_all();

                    // remove from pending queue
                    // pending_socks.remove(&sock_entry);

                    // TODO: additional processing of data
                    // ...
                } // else { drop } -> if outside window, drop segment
            } else {
                // if in last ACK, delete da boi
                if snd.nxt == ack_no && tcp_state == TCPState::LastAck {
                    // remove from pending sockets; we've been noticed senpai uWu~
                    // XXX: will this deadlock?
                    pending_socks.remove(&sock_entry);
                    // TODO: other cleanup
                    sockets.delete_socket_by_entry(&sock_entry);
                    continue;
                }

                let r_closed = sock.r_closed();
                let old_una = snd.una;
                // determine if we should send more segments
                let mut wnd_update = false;
                // determine if we should add to pending queue
                let mut is_pending = false;

                // if ACK in [SND.UNA ... SND.UNA + SND.NXT] and not r_closed, update send window
                if snd.in_una_nxt_window(ack_no) && !r_closed {
                    // eprintln!("[segment_loop] updating window...");
                    snd.wnd = seg_wnd;
                    wnd_update = true;
                }

                // eprintln!(
                // "[segment_loop] data.len(): {}, ack: {}, una: {}, nxt: {}",
                // tcp_seg.data.len(),
                // ack_no,
                // snd.una,
                // snd.nxt
                // );

                // if ACK in (SND.UNA ... SND.UNA + SND.NXT], update send variables
                if ack_no != old_una && snd.in_una_nxt_window(ack_no) && !r_closed {
                    // hacky solution: if in closing state, artificially increase LEN
                    if tcp_state.closing() {
                        snd.len += 1;
                    }
                    snd.set_una(seq_no, ack_no, seg_wnd);

                    // if len -> 0, notify CV
                    if snd.len == 0 {
                        let (_, cv) = &*sock.pending.clone();
                        cv.notify_all();
                    }
                }

                // if not fin/still can read and has data:
                if (!fin || tcp_state.readable()) && !tcp_seg.data.is_empty() {
                    // fill up receive buffer [TODO: move into process_data method]
                    if let Err(e) = rcv.write(tcp_seg.data.as_slice(), seq_no) {
                        eprintln!("[segment_loop] {}", e);
                    }
                }

                // if fin and should be next RCV, update rcv.nxt
                if fin && rcv.nxt == seq_no {
                    eprintln!("[segment_loop] got fin");
                    rcv.nxt += 1;
                }

                // decide whether to send more data, or just ack
                let off = snd.nxt as usize - if tcp_state.writable() { 0 } else { 1 };
                let mut send_more = snd.bytes_left(off % snd.capacity()) > 0 && snd.wnd > 0;

                // before we update, record if we should send an ack back
                let mut should_send_ack =
                    (fin && tcp_state.should_send_ack()) || !tcp_seg.data.is_empty();

                // if window updated, check status of zero probing
                if wnd_update {
                    // if window > 0 and zero probing, stop and potentially start sending
                    if seg_wnd > 0 && sock.is_zero_probing() {
                        eprintln!("[segment_loop] stopping zero probing...");

                        sock.stop_zero_probing();
                        // eprintln!("[segment_loop] snd.is_empty: {}", snd.is_empty());
                    } else if seg_wnd == 0 {
                        // otherwise: can't send any, window is poopoo
                        send_more = false;
                        // if already zero probing, just increment zp_counter
                        if sock.is_zero_probing() {
                            sock.inc_zp_counter();

                            eprintln!("[segment_loop] already zero-probing");
                            // XXX: should I need to add to pending here?
                            is_pending = true;
                        } else {
                            // get byte from end, if applicable
                            if let Some(end) = snd.get_end() {
                                eprintln!("[segment_loop] starting zero probing...");

                                // TODO: check this. I think we only need to start zero probing if
                                // there are bytes at the end
                                // initialize zero probing
                                sock.start_zero_probing();
                                // clear retransmission queue; shouldn't retransmit anything
                                sock.rtx_q_clear();
                                // end_byte: u8, SEQ, ACK, WND
                                sock.send_bytes(vec![end], snd.nxt, rcv.nxt, rcv.wnd).ok();
                                // update snd.nxt
                                snd.nxt += 1;
                                // mark as pending
                                is_pending = true;
                            } else {
                                eprintln!(
                                    "[segment_loop] nothing left; snd.is_empty(): {}",
                                    snd.is_empty()
                                );

                                // if None, we'll send an ack later
                                should_send_ack = true;
                            }
                        }
                    }
                }

                // TODO: retransmission queue shenanigans
                match tcp_state {
                    TCPState::Established => {
                        if fin {
                            sock.set_tcp_state(TCPState::CloseWait);
                            // if move to close wait, notify recv CV; no more reading
                            rcv.cv.notify_all();
                        }
                    }
                    // if in FinWait1, move to TimeWait, FinWait2, or Closing depending on value
                    TCPState::FinWait1 => {
                        if fin && snd.nxt == ack_no {
                            sock.set_tcp_state(TCPState::TimeWait);
                            // initialize timer, and mark to insert into pending socks
                            sock.start_time_wait();
                            is_pending = true;
                            // notify CV that we're done
                            let (_, cv) = &*sock.pending.clone();
                            cv.notify_all();
                        } else if snd.nxt == ack_no {
                            sock.set_tcp_state(TCPState::FinWait2);
                        } else if fin {
                            sock.set_tcp_state(TCPState::Closing);
                        } else {
                            // eprintln!(
                            // "[segment_loop] SND.NXT != ACK_NO and not FIN for {}",
                            // tcp_state
                            // );
                        }
                    }
                    TCPState::FinWait2 => {
                        if fin {
                            sock.set_tcp_state(TCPState::TimeWait);
                            // initialize timer, and insert into pending socks
                            sock.start_time_wait();
                            is_pending = true;
                            // notify CV that we're done
                            let (_, cv) = &*sock.pending.clone();
                            cv.notify_all();
                        }
                    }
                    // if in Closing, move to TimeWait
                    TCPState::Closing => {
                        // only update if ACKed our fin
                        if snd.nxt == ack_no {
                            sock.set_tcp_state(TCPState::TimeWait);
                            // initialize timer, and insert into pending socks
                            sock.start_time_wait();
                            is_pending = true;

                            // notify CV that we're done
                            let (_, cv) = &*sock.pending.clone();
                            cv.notify_all();
                        } else {
                            eprintln!("[segment_loop] SND.NXT != ACK_NO for Closing");
                        }
                    }
                    _ => (),
                };

                // if can send more data, do it
                if send_more {
                    // get segments and send [XXX: una_segments or nxt_segments]
                    let segments = snd.get_nxt_segments(MSS);
                    sock.send_segments(segments, Some((rcv.nxt, rcv.wnd))).ok();

                    // we've sent something, so must be pending
                    is_pending = true;
                } else if should_send_ack {
                    sock.send_ack(snd.nxt, rcv.nxt, rcv.wnd).ok();
                }

                // TODO: hopefully this fixes my deadlock
                drop(snd);
                drop(rcv);

                // if necessary, insert into pending_socks
                if is_pending {
                    pending_socks.insert(sock_entry);
                }
            }
        }

        eprintln!("segment loop terminated.");
    })
}

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
        // segment), we can unwrap the socket from the socket entry.
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

        // update PRTT based on RTT, if applicable
        // sock.update_prtt(Instant::now());

        // repackage IPPacket, since we'll need to forward
        let packet = IPPacket {
            header: ip_hdr,
            payload: tcp_seg.to_bytes()?,
        };
        //// Forward, based on TCP State:
        let syn = tcp_seg.header.syn;
        let ack = tcp_seg.header.ack;

        let tcp_state = sock.get_tcp_state();
        // If LISTEN, forward to accept_loop only if SYN packet
        if tcp_state == TCPState::Listen {
            if ack {
                return Err(Error::new(ErrorKind::ConnectionRefused, "no ACK listen!"));
            } else if syn {
                if accept_tx.send(packet).is_ok() {}
            } else {
                eprintln!("[tcp_handler] TODO: more informative error message");
            }
        // } else if pending_socks.contains(&sock_entry) {
        // // TODO: should we offload to segment_loop, or just do checks here?
        // let ackno = tcp_seg.header.acknowledgment_number;
        // // ensure that ACKNO is in correct spot; if so, send to segment_loop
        // if snd.una <= ackno && ackno <= snd.nxt {
        // segment_tx.send(packet).ok();
        // }
        // // if Established, should be able to receive segments
        } else {
            // other stuff TODO: like whatttt
            segment_tx.send(packet).ok();
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
