pub mod concurrent_queue;
pub mod socket_table;
pub mod tcp_segment;
pub mod tcp_socket;
pub mod tcp_utils;

use dashmap::{iter::Iter, DashMap, DashSet};
use etherparse::{Ipv4Header, TcpHeader};
// use threadpool::ThreadPool;

use std::{
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
        Arc, Mutex, RwLock,
    },
    thread::JoinHandle,
};

use self::{concurrent_queue::*, socket_table::*, tcp_segment::*, tcp_socket::*, tcp_utils::*};
use crate::protocol::network::{ip_packet::*, Handler, InternetModule};

pub const TCP_PROTOCOL: u8 = 6;
pub const TCP_TTL: u8 = 60;

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
    listen_queue: Arc<DashMap<SocketEntry, ConcurrentQueue<SocketID>>>,
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
    pub fn v_listen(&self, addr: Ipv4Addr, port: u16) -> Result<SocketID> {
        // check if addr valid, i.e. not used
        let src_sock = SocketAddrV4::new(addr, port);
        let zero_sock = SocketAddrV4::new(0.into(), 0);
        let sock_entry = SocketEntry {
            src_sock,
            dst_sock: zero_sock,
        };
        if self.sockets.has_entry(&sock_entry) {
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("[v_listen] socket {}:{} already in use!", addr, port),
            ));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.sockets.insert_entry(
            id,
            sock_entry.clone(),
            Socket::new(src_sock, zero_sock, TCPState::Listen, self.send_tx.clone()),
        );
        // open listen queue for waiting
        self.listen_queue.insert(sock_entry, ConcurrentQueue::new());

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
        let mut sock = Socket::new(src_sock, dst_sock, TCPState::SynSent, self.send_tx.clone());
        // set socket values
        let isn = 0; // TODO: better ISN selection
        sock.snd.iss = isn;
        sock.snd.una = isn;
        sock.snd.nxt = isn + 1;

        // send SYN segment
        if sock.send_syn(dst_sock).is_ok() {}

        // insert into pending socks
        self.pending_socks.insert(sock_entry.clone());

        // insert into socket table
        self.sockets.insert_entry(id, sock_entry, sock);

        Ok(id)
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
     * Get formatted sockets string.
     */
    pub fn fmt_sockets(&self) -> String {
        let mut res = String::new();
        res.push_str("socket\tlocal-addr\tport\t\tdst-addr\tport\tstatus\n");
        res.push_str("-------------------------------------------------------------------\n");

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

            res.push_str(
                &(format!(
                    "{}\t{}\t{}\t\t{}\t{}\t{}",
                    id,
                    src_addr.to_string() + extra_tab,
                    src_port,
                    dst_addr.to_string() + extra_tab,
                    dst_port,
                    se.value().tcp_state
                )),
            );
            if index != self.sockets.len() - 1 {
                res.push('\n');
            }
        }

        res
    }
}
