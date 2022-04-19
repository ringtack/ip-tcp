pub mod tcp_socket;

use etherparse::TcpHeader;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
};

use crate::protocol::network::{ip_packet::*, *};

use self::tcp_socket::*;

pub const TCP_PROTOCOL: u8 = 6;
pub const ZERO_SOCK: SocketAddrV4 = SocketAddrV4::new([0, 0, 0, 0].into(), 0);

type SocketID = u8;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SocketEntry {
    src_sock: SocketAddrV4,
    dst_sock: SocketAddrV4,
}

pub struct TCPLayer {
    next_id: SocketID,
    socket_ids: HashMap<SocketID, SocketEntry>,
    sockets: HashMap<SocketEntry, Socket>,
    //
    accepting: HashMap<SocketAddrV4, Sender<SocketAddrV4>>,
    listeners: HashMap<SocketAddrV4, Receiver<SocketAddrV4>>,
    ip_module: InternetModule,
}

impl TCPLayer {
    pub fn new(ip_module: InternetModule) -> TCPLayer {
        TCPLayer {
            next_id: 0,
            socket_ids: HashMap::new(),
            sockets: HashMap::new(),
            accepting: HashMap::new(),
            listeners: HashMap::new(),
            ip_module,
        }
    }

    pub fn v_listen(&mut self, addr: Ipv4Addr, port: u16) -> SocketID {
        // check if addr valid

        let src_sock = SocketAddrV4::new(addr, port);
        let socket_entry = SocketEntry {
            src_sock,
            dst_sock: ZERO_SOCK,
        };

        if self.sockets.contains_key(&socket_entry) {
            return u8::MAX;
        }

        let id = self.next_id;
        self.next_id += 1;

        self.socket_ids.insert(id, socket_entry.clone());
        self.sockets.insert(
            socket_entry,
            Socket::new(src_sock, ZERO_SOCK, TCPState::Listen),
        );

        let (tx, rx) = mpsc::channel::<SocketAddrV4>();
        self.accepting.insert(src_sock, tx);
        self.listeners.insert(src_sock, rx);

        id
    }

    pub fn v_accept(&mut self, id: SocketID) -> Result<SocketID> {
        let sock_entry = &self.socket_ids[&id];
        let src_sock = sock_entry.src_sock;

        // check if LISTEN state

        // upon receiving SYN packet
        match self.listeners[&src_sock].recv() {
            Ok(dst_sock) => {
                // check LISTEN state

                // create new socket [NOTE: don't need to update port here!]
                let sock_entry = SocketEntry { src_sock, dst_sock };
                self.sockets.insert(
                    sock_entry,
                    Socket::new(src_sock, dst_sock, TCPState::SynRcvd),
                );

                // send SYN+ACK packet
                let (src_addr, src_port) = (src_sock.ip(), src_sock.port());
                let (dst_addr, dst_port) = (dst_sock.ip(), dst_sock.port());
                let mut packet = TCPPacket::new(src_port, dst_port, 0, 16, Vec::new());

                packet.header.syn = true;
                packet.header.ack = true;

                let packet =
                    IPPacket::new(*src_addr, *dst_addr, packet.to_bytes()?, 16, TCP_PROTOCOL);

                self.ip_module.send_ip(packet)?;
            }
            Err(e) => eprintln!("{}", e),
        }

        match self.listeners[&src_sock].recv() {
            Ok(dst_sock) => {
                // if here, that means we received ACK, and can set to established
                let sock_entry = SocketEntry { src_sock, dst_sock };

                // TODO: update src_port here!!!!
                // self.sockets.get_mut(&sock_entry).unwrap().tcp_state = TCPState::Established;

                // probably just return ID?
                return Ok(u8::MAX);
            }
            Err(e) => eprintln!("{}", e),
        }

        // TODO: fix
        Ok(u8::MAX)
    }
}

pub fn make_tcp_handler(tcp_layer: Arc<Mutex<TCPLayer>>) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let (header, payload) = (packet.header, packet.payload);
        let tcp_packet = TCPPacket::from_bytes(&payload)?;

        let tcp_layer = tcp_layer.lock().unwrap();

        // check socket in table
        let src_sock =
            SocketAddrV4::new(Ipv4Addr::from(header.source), tcp_packet.header.source_port);
        let dst_sock = SocketAddrV4::new(
            Ipv4Addr::from(header.destination),
            tcp_packet.header.destination_port,
        );

        let sock_entry = SocketEntry { src_sock, dst_sock };

        Ok(())
    }))
}

pub struct TCPPacket {
    pub header: TcpHeader,
    pub payload: Vec<u8>,
}

impl TCPPacket {
    pub fn new(
        src_port: u16,
        dst_port: u16,
        seq_no: u32,
        win_size: u16,
        payload: Vec<u8>,
    ) -> TCPPacket {
        TCPPacket {
            header: TcpHeader::new(src_port, dst_port, seq_no, win_size),
            payload,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // convert packet into bytes
        let mut header_bytes = Vec::<u8>::with_capacity(self.header.header_len() as usize);
        // need custom check to convert to correct error type; this computes checksum!
        if let Err(e) = self.header.write(&mut header_bytes) {
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }

        // TODO: fix cloning...
        // combine into one byte vector
        header_bytes.extend(self.payload.clone());
        Ok(header_bytes)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<TCPPacket> {
        // custom handling (since from_slice gives a weird error :/)
        match TcpHeader::from_slice(buf) {
            Ok((header, buf)) => {
                // checksum validation
                // if header.calc_header_checksum().unwrap() != header.header_checksum {
                // println!("checksum validation failed");

                // return Err(Error::new(ErrorKind::Other, "checksum validation failed"));
                // }

                // subtract number of bytes read into header from remaining bytes
                let num_bytes = buf.len();
                // get IP payload from L2 payload
                let mut payload = Vec::<u8>::with_capacity(num_bytes);
                payload.extend_from_slice(&buf[..num_bytes]);
                // return packet
                Ok(TCPPacket { header, payload })
            }
            Err(e) => {
                println!("Failed to convert packet to slice");
                Err(Error::new(ErrorKind::Other, e.to_string()))
            }
        }
    }
}
