pub mod control_buffers;
pub mod socket_table;
pub mod synchronized_queue;
pub mod tcp_errors;
pub mod tcp_retransmit;
pub mod tcp_segment;
pub mod tcp_socket;
pub mod tcp_utils;

use dashmap::{iter::Iter, DashMap, DashSet};
use etherparse::{Ipv4Header, TcpHeader};
use snafu::prelude::*;

use std::{
    collections::HashSet,
    fs::File,
    io::{prelude::*, BufReader, BufWriter, Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
        Arc, Mutex, RwLock,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use self::{
    socket_table::*, synchronized_queue::*, tcp_errors::*, tcp_retransmit::*, tcp_segment::*,
    tcp_socket::*, tcp_utils::*,
};
use crate::protocol::network::{ip_packet::*, Handler, InternetModule};

pub const TCP_PROTOCOL: u8 = 6;
pub const TCP_TTL: u8 = 60;
pub const RWBUF_SIZE: usize = 5 * MSS;

pub const SYN_TIMEOUT: u64 = 10; // in secs
pub const CV_TIMEOUT: u64 = 1000; // in MS

type SocketID = u8;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SocketEntry {
    src_sock: SocketAddrV4,
    dst_sock: SocketAddrV4,
}

pub struct TCPModule {
    //// ID of next socket; currently only counts up
    next_id: Arc<AtomicU8>,

    //// IP Module: use to send across Internet
    ip_module: InternetModule,

    //// Socket Table: store list of all sockets
    pub sockets: SocketTable,

    //// Listen and Pending (i.e. timed; TODO: perhaps change) connections
    // add to listen queue once passive OPEN spawns -> SYN_RCVD socket
    listen_queue: Arc<DashMap<SocketEntry, SynchronizedQueue<SocketID>>>,
    // add to pending queue once v_connect -> SYN_SENT, passive OPEN -> SYN_RCVD, or sync-SYN
    pub pending_socks: Arc<DashSet<SocketEntry>>,

    //// Channels for concurrent processing
    // clone for every Socket, receive in send_loop
    send_tx: SyncSender<IPPacket>,
    // send in TCP Handler, handle in accept_loop
    pub accept_tx: Sender<IPPacket>,
    // send in TCP Handler, handle in segment_loop
    pub segment_tx: Sender<IPPacket>,
    //// Thread pool to assist in segment_loop [TODO: and other handlers?]
    // t_pool: Arc<ThreadPool>,

    //// Cleanup [TODO: do I need, or can I just detach? Or initialize in Node?]
    thrs: Vec<JoinHandle<()>>,
}

impl Clone for TCPModule {
    fn clone(&self) -> TCPModule {
        TCPModule {
            next_id: self.next_id.clone(),
            ip_module: self.ip_module.clone(),
            sockets: self.sockets.clone(),
            listen_queue: self.listen_queue.clone(),
            pending_socks: self.pending_socks.clone(),
            send_tx: self.send_tx.clone(),
            accept_tx: self.accept_tx.clone(),
            segment_tx: self.segment_tx.clone(),
            thrs: Vec::new(),
        }
    }
}

impl TCPModule {
    /**
     * Creates a TCP module given an IP module.
     */
    pub fn new(ip_module: InternetModule) -> TCPModule {
        let (send_tx, send_rx) = mpsc::sync_channel(CHAN_BOUND);
        let (accept_tx, accept_rx) = mpsc::channel();
        let (segment_tx, segment_rx) = mpsc::channel();
        let mut tcp_module = TCPModule {
            next_id: Arc::new(AtomicU8::new(0)),
            ip_module: ip_module.clone(),
            sockets: SocketTable::new(),
            listen_queue: Arc::new(DashMap::new()),
            pending_socks: Arc::new(DashSet::new()),
            send_tx: send_tx.clone(),
            accept_tx,
            segment_tx,
            // t_pool: Arc::new(ThreadPool::new(N_THREADS)),
            thrs: Vec::new(),
        };

        /* ====================================================================
         * Thread Handlers Setup
         * ====================================================================
         */
        tcp_module.thrs.push(make_send_loop(send_rx, ip_module));
        tcp_module.thrs.push(make_accept_loop(
            accept_rx,
            send_tx,
            tcp_module.sockets.clone(),
            tcp_module.pending_socks.clone(),
            tcp_module.listen_queue.clone(),
            tcp_module.next_id.clone(),
        ));
        tcp_module.thrs.push(make_segment_loop(
            segment_rx,
            tcp_module.sockets.clone(),
            tcp_module.pending_socks.clone(),
        ));
        tcp_module.thrs.push(check_retransmission(
            tcp_module.sockets.clone(),
            tcp_module.pending_socks.clone(),
        ));
        tcp_module.thrs.push(dead_socket_handler(
            tcp_module.sockets.clone(),
            tcp_module.pending_socks.clone(),
        ));

        tcp_module
    }

    /**
     * Creates a new socket and binds the socket to an address/port. If addr is nil/0, bind to any
     * available interface.
     *
     * After binding, moves socket into LISTEN state (passive OPEN in the RFC).
     *
     * Returns:
     * - socket number on success or negative number on failure
     */
    pub fn v_listen(&self, addr: Ipv4Addr, port: u16) -> TCPResult<SocketID> {
        // enforce that port >= 1024
        ensure!(port >= 1024, AddrInUseSnafu { addr, port });

        // check if addr valid, i.e. not used
        let src_sock = SocketAddrV4::new(addr, port);
        let zero_sock = SocketAddrV4::new(0.into(), 0);
        let sock_entry = SocketEntry {
            src_sock,
            dst_sock: zero_sock,
        };
        ensure!(
            !self.sockets.has_entry(&sock_entry),
            AddrInUseSnafu { addr, port }
        );

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.sockets.insert_entry(
            id,
            sock_entry.clone(),
            Socket::new(src_sock, zero_sock, TCPState::Listen, self.send_tx.clone()),
        );
        // open listen queue for waiting
        self.listen_queue
            .insert(sock_entry, SynchronizedQueue::new());

        // id
        Ok(id)
    }

    /**
     * Accept a requested connection from the listening socket's connection queue.
     *
     * Returns:
     * - new socket handle on success or error on failure
     */
    pub fn v_accept(&self, id: SocketID) -> Result<SocketID> {
        // pretty simple; just wait for a socket from the listener socket!
        let sock_entry = match self.sockets.get_socket_entry(id) {
            Some(sock_entry) => sock_entry,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "[v_accept] EBADF: invalid socket ID!",
                ));
            }
        };
        let mut listener_queue = self.listen_queue.get(&sock_entry).unwrap().clone();

        if let Some(cid) = listener_queue.pop() {
            Ok(cid)
        } else {
            Err(Error::new(
                ErrorKind::BrokenPipe,
                "[v_accept] EINVAL: network down!",
            ))
        }
    }

    /**
     * Creates a new socket and connects to an address (active OPEN in the RFC).
     *
     * Returns:
     * -  the socket number on success, or Err on failure
     */
    pub fn v_connect(&self, addr: Ipv4Addr, port: u16) -> Result<SocketID> {
        let gateway_addr = match self.ip_module.get_gateway(&addr) {
            Some(gateway_addr) => gateway_addr,
            None => {
                return Err(Error::new(
                    ErrorKind::AddrNotAvailable,
                    "address not reachable!",
                ))
            }
        };

        // create SocketEntry for new connection
        let dst_sock = SocketAddrV4::new(addr, port);
        let src_sock = SocketAddrV4::new(
            gateway_addr,
            find_valid_port(&dst_sock, gateway_addr, &self.sockets),
        );
        let sock_entry = SocketEntry { src_sock, dst_sock };

        // create socket ID and socket
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let sock = Socket::new(src_sock, dst_sock, TCPState::SynSent, self.send_tx.clone());
        let isn = 0; // TODO: better ISN selection
                     // set socket values
        let mut snd = sock.snd.lock().unwrap();
        snd.set_iss(isn);
        drop(snd);

        // send SYN segment
        if sock.send_syn(dst_sock, isn).is_ok() {}

        // insert into socket table
        self.sockets.insert_entry(id, sock_entry.clone(), sock);

        // insert into pending socks
        self.pending_socks.insert(sock_entry);

        Ok(id)
    }

    /**
     * Read on an open socket (RECEIVE in the RFC). REQUIRED to block when there is no available
     * data. All reads should return at least one data byte unless failure or EOF occurs.
     *
     * Returns:
     * - (num bytes read) or (negative number on failure) or (0 on EOF and shutdown_read) or (0 if
     * nbyte = 0)
     */
    pub fn v_read(&self, id: SocketID, buf: &mut [u8], n_bytes: usize) -> TCPResult<usize> {
        if n_bytes == 0 {
            return Ok(0);
        }

        // attempt to find socket associated with ID
        let sock = self
            .sockets
            .get_socket_by_id(id)
            .context(BadFdSnafu { sock_id: id })?;

        let tcp_state = sock.get_tcp_state();
        if !tcp_state.readable() || (tcp_state == TCPState::CloseWait && sock.get_rcv_len() == 0) {
            return InvalidStateSnafu {
                tcp_state,
                command: String::from("v_read"),
            }
            .fail();
        }

        // if already stopped, emit error
        if sock.r_closed.load(Ordering::Relaxed) {
            return InvalidArgumentsSnafu {
                error: String::from("[EINVAL] Socket closed for reading."),
            }
            .fail();
        }

        // propagate errors; specifically, will either give # bytes read, or error if closed
        sock.recv_buffer(buf, n_bytes)
    }

    /**
     * Write on an open socket (SEND in the RFC). Write is REQUIRED to block until all bytes are in
     * the send buffer.
     *
     * Returns:
     * - (num bytes written) or (negative number on failure)
     */
    pub fn v_write(&self, id: SocketID, buf: &[u8]) -> TCPResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // attempt to find socket associated with ID
        let sock = self
            .sockets
            .get_socket_by_id(id)
            .context(BadFdSnafu { sock_id: id })?;

        // if not writable, return error
        if !sock.get_tcp_state().writable() {
            return InvalidArgumentsSnafu {
                error: String::from("[EINVAL] Socket be in either ESTAB or CLOSE_WAIT."),
            }
            .fail();
        }

        let n_wrote = sock.send_buffer(buf)?;

        // insert into pending sockets
        self.pending_socks
            .insert(self.sockets.get_socket_entry(id).unwrap());

        Ok(n_wrote)
    }

    /**
     * Shutdown an connection.
     *
     * - if `how` is WriteClose, close the writing part (CLOSE from RFC, i.e. send FIN)
     * - if `how` is ReadClose, close the reading part (no equivalent; all v_reads should return
     * 0).
     * - if `how` is BothClose, close both ends.
     *
     * Returns:
     * - nothing on success, error on failure.
     */
    pub fn v_shutdown(&self, id: SocketID, how: ShutdownType) -> TCPResult<()> {
        // attempt to find socket associated with ID
        let sock = self
            .sockets
            .get_socket_by_id(id)
            .context(BadFdSnafu { sock_id: id })?;

        let tcp_state = sock.get_tcp_state();
        let (src_sock, dst_sock) = self.get_sock_entry(id).unwrap();
        let sock_entry = SocketEntry { src_sock, dst_sock };

        // if in Listen or SynSent, delete TCB
        if tcp_state.can_delete() {
            self.sockets.delete_socket_by_entry(&sock_entry);
            return Ok(());
        }

        if !tcp_state.can_shutdown() {
            return InvalidArgumentsSnafu {
                error: String::from("[EINVAL] socket must either be Established or CloseWait."),
            }
            .fail();
        }

        // on write/both close:
        if how == ShutdownType::Write || how == ShutdownType::Both {
            // send FIN packet
            if sock.send_fin().is_ok() {}
            // change state to FinWait1 or LastAck, depending on state
            if tcp_state == TCPState::Established {
                sock.set_tcp_state(TCPState::FinWait1);
                // add to pending sockets queue
                self.pending_socks.insert(sock_entry);
            } else {
                // otherwise, just change to LastAck
                // [TODO: can't remove from pending queue yet, unless we have separate TimeWait
                // thread?]
                sock.set_tcp_state(TCPState::LastAck);
            }
            // mark for timeout
            sock.start_time_wait();
        }
        // on read/both close:
        if how == ShutdownType::Read || how == ShutdownType::Both {
            // just mark socket as closed; further reads should fail
            sock.r_closed.store(true, Ordering::Relaxed);
        }
        // on success, return 0.
        Ok(())
    }

    /**
     * Close the socket, making the underlying connection inaccessible to the TCP API functions.
     * The connection will finish retransmitting any data not yet ACK'd.
     *
     * Returns:
     * - Nothing on success, error on failure.
     */
    pub fn v_close(&self, id: SocketID) -> TCPResult<()> {
        // attempt to find socket associated with ID
        let sock_entry = self
            .sockets
            .get_socket_entry(id)
            .context(BadFdSnafu { sock_id: id })?;
        let sock = self.sockets.get_socket_by_entry(&sock_entry).unwrap();

        // send FIN to the other end
        sock.set_tcp_state(TCPState::FinWait1);
        sock.send_fin().ok();

        // merk it from the socket list
        self.sockets.delete_socket_by_entry(&sock_entry);

        Ok(())
    }

    /**
     * Close all sockets.
     */
    pub fn close_all(&self) {
        let mut to_delete = HashSet::new();
        for sock in self.sockets.iter() {
            sock.set_tcp_state(TCPState::FinWait1);
            sock.send_fin().ok();
            to_delete.insert(sock.key().clone());
        }
        for sock_entry in to_delete {
            self.sockets.delete_socket_by_entry(&sock_entry);
        }
    }

    /**
     * Helper function to send a file through a socket.
     *
     * Inputs:
     * - addr: the destination address
     * - port: the destination port
     * - filename: the input file's path
     *
     * Returns:
     * - The duration and bytes sent, or None if error
     */
    pub fn send_file(
        &self,
        addr: Ipv4Addr,
        port: u16,
        filename: String,
    ) -> Option<(Duration, usize)> {
        let cv_timeout = Duration::from_millis(CV_TIMEOUT);

        // connect to desired port
        let cid = match self.v_connect(addr, port) {
            Ok(c_id) => c_id,
            Err(e) => {
                eprintln!("{}", e);
                return None;
            }
        };

        // wait until Established
        let sock = self.get_sock(cid).unwrap();
        let (mtx, cv) = &*sock.pending;
        let mut m = mtx.lock().unwrap();
        // set expiration; if doesn't work after 10 seconds, return 0 for both (SYN timeout is 1 +
        // 2 + 4 = 7s)
        let syn_wait = Instant::now();
        let wait_timeout = Duration::from_secs(SYN_TIMEOUT);
        while sock.get_tcp_state() != TCPState::Established {
            m = cv.wait_timeout(m, cv_timeout).unwrap().0;
            // if timeout, return error
            if syn_wait.elapsed() > wait_timeout {
                return Some((Duration::ZERO, 0));
            }
        }
        drop(m);

        // now, open file for reading
        let f = match File::open(filename) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{e}");
                self.v_shutdown(cid, ShutdownType::Both).ok();
                return None;
            }
        };

        let mut f = BufReader::new(f);
        let mut buf = vec![0; RWBUF_SIZE];
        // for logging purposes
        let mut total_bytes = 0;
        let start = Instant::now();
        loop {
            match f.read(&mut buf) {
                Ok(n_read) => {
                    // println!("writing {n_read} bytes");
                    if n_read == 0 {
                        break;
                    }
                    total_bytes += n_read;
                    match self.v_write(cid, &buf[..n_read]) {
                        Ok(_) => (),
                        Err(e) => {
                            // if got here, probably manually shut down
                            eprintln!("{e}");
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    self.v_shutdown(cid, ShutdownType::Both).ok();
                    return None;
                }
            }
        }
        // wait until we've sent all
        let mut m = mtx.lock().unwrap();
        while sock.get_snd_len() > 0 {
            m = cv.wait(m).unwrap();
        }
        drop(m);

        let elapsed = start.elapsed();

        // now, we're done writing, so shut down writing side, if not already
        if sock.get_tcp_state().can_shutdown() {
            self.v_shutdown(cid, ShutdownType::Write).ok();
        }

        // wait until socket reaches TimeWait state, or timeout
        let mut m = mtx.lock().unwrap();
        let time_wait = Instant::now();
        while sock.get_tcp_state() != TCPState::TimeWait {
            m = cv.wait_timeout(m, cv_timeout).unwrap().0;
            if time_wait.elapsed() > wait_timeout {
                // doesn't matter too much, already sent everything, so just quit
                break;
            }
        }
        drop(m);

        Some((elapsed, total_bytes))
    }

    /**
     * Helper function to receive a file on a port.
     *
     * Inputs:
     * - port: the source port
     * - filename: the output file's path
     *
     * Returns:
     * - The time elapsed and number of bytes sent, or an error
     */
    pub fn recv_file(&self, port: u16, filename: String) -> Option<(Duration, usize)> {
        let cv_timeout = Duration::from_millis(CV_TIMEOUT);

        // listen on the desired port
        let lid = match self.v_listen(0.into(), port) {
            Ok(l_id) => l_id,
            Err(e) => {
                eprintln!("{}", e);
                return None;
            }
        };
        // accept a connection from the listening socket
        let cid = match self.v_accept(lid) {
            Ok(c_id) => c_id,
            Err(e) => {
                eprintln!("{e}");
                return None;
            }
        };
        // once we've connected, close mr listener
        match self.v_shutdown(lid, ShutdownType::Both) {
            Ok(()) => (),
            Err(e) => {
                eprintln!("{e}");
                self.v_shutdown(cid, ShutdownType::Both).ok();
                return None;
            }
        };
        // wait until established
        let sock = self.get_sock(cid).unwrap();
        let (mtx, cv) = &*sock.pending;
        let mut m = mtx.lock().unwrap();
        // set expiration; if doesn't work after 10 seconds, return 0 for both (SYN timeout is 1 +
        // 2 + 4 = 7s)
        let rcv_wait = Instant::now();
        let wait_timeout = Duration::from_secs(SYN_TIMEOUT);
        while sock.get_tcp_state() != TCPState::Established {
            m = cv.wait_timeout(m, cv_timeout).unwrap().0;
            if rcv_wait.elapsed() > wait_timeout {
                return Some((Duration::ZERO, 0));
            }
        }
        drop(m);

        // now, open file for writing
        let f = match File::create(&filename) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{e}");
                self.v_shutdown(cid, ShutdownType::Both).ok();
                return None;
            }
        };
        let mut f = BufWriter::new(f);

        // to store what is read
        let mut buf = vec![0; RWBUF_SIZE];
        // for logging purposes
        let start = Instant::now();
        let mut total_bytes = 0;
        while let Ok(n_read) = self.v_read(cid, &mut buf, RWBUF_SIZE) {
            total_bytes += n_read;
            f.write_all(&buf[..n_read]).ok();
        }

        // now, we've received FIN, so shut down both
        self.v_shutdown(cid, ShutdownType::Both).ok();
        // flush file; we are done!
        f.flush().ok();

        Some((Instant::now().duration_since(start), total_bytes))
    }

    /**
     * Get information about a socket ID.
     */
    pub fn get_sock_entry(&self, id: SocketID) -> Option<(SocketAddrV4, SocketAddrV4)> {
        self.sockets
            .get_socket_entry(id)
            .map(|sock_entry| (sock_entry.src_sock, sock_entry.dst_sock))
    }

    /**
     * Get a socket from its ID.
     */
    pub fn get_sock(&self, id: SocketID) -> Option<Socket> {
        self.sockets.get_socket_by_id(id)
    }

    /**
     * Get formatted sockets string.
     */
    pub fn fmt_sockets(&self) -> String {
        let mut res = String::new();
        res.push_str("socket\tlocal-addr\tport\t\tdst-addr\tport\tstatus\n");
        res.push_str("----------------------------------------------------------------------\n");

        for (index, se) in self.sockets.iter().enumerate() {
            let id = self.sockets.get_socket_id(se.key()).unwrap();
            let (src_sock, dst_sock) = (se.key().src_sock, se.key().dst_sock);
            let (src_addr, src_port) = (*src_sock.ip(), src_sock.port());
            let (dst_addr, dst_port) = (*dst_sock.ip(), dst_sock.port());

            let extra_tab = if src_addr == Ipv4Addr::from(0) {
                "\t"
            } else {
                ""
            };

            let tcp_state = se.value().tcp_state.lock().unwrap();
            res.push_str(
                &(format!(
                    "{}\t{}\t{}\t\t{}\t{}\t{}",
                    id,
                    src_addr.to_string() + extra_tab,
                    src_port,
                    dst_addr.to_string() + extra_tab,
                    dst_port,
                    *tcp_state
                )),
            );
            if index != self.sockets.len() - 1 {
                res.push('\n');
            }
        }

        res
    }

    // TODO: REMOVE, JUST FOR LOGGING
    pub fn log_socket_buffers(&self, id: SocketID) -> TCPResult<()> {
        // attempt to find socket associated with ID
        let sock = self
            .sockets
            .get_socket_by_id(id)
            .context(BadFdSnafu { sock_id: id })?;

        let (snd, rcv) = (sock.snd.lock().unwrap(), sock.rcv.lock().unwrap());
        println!("{}\n{}", snd, rcv);
        Ok(())
    }
}
