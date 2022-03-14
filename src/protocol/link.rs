use std::io::{self, Error, ErrorKind};
use std::net;

const MTU: usize = 1400;

pub struct LinkInterface {
    socket: net::UdpSocket,
    socket_addr: net::SocketAddrV4,
    active: bool,
}

pub struct LinkPayload {
    buf: [u8; MTU],
    len: usize,
}

impl LinkInterface {
    pub fn new(socket_addr: net::SocketAddrV4) -> Result<LinkInterface, Error> {
        // let socket_addr = net::SocketAddrV4::new(phys_addr, port);
        let link_interface = LinkInterface {
            socket: net::UdpSocket::bind(socket_addr)?,
            socket_addr,
            active: true,
        };
        Ok(link_interface)
    }

    pub fn link_up(&mut self) {
        self.active = true;
    }

    pub fn link_down(&mut self) {
        self.active = false;
    }

    pub fn send_link_frame(
        &self,
        other: &LinkInterface,
        payload: &LinkPayload,
    ) -> Result<usize, io::Error> {
        if !self.active {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "sending to unreachable address",
            ));
        }
        self.socket.send_to(&payload.buf, other.socket_addr)
    }

    pub fn recv_link_frame(&self) -> Result<(net::SocketAddr, LinkPayload), Error> {
        if !self.active {
            return Err(Error::new(ErrorKind::NotConnected, "Link is down."));
        }
        let mut payload = LinkPayload {
            buf: [0; 1400],
            len: 0,
        };
        let (num_bytes, src_addr) = self.socket.recv_from(&mut payload.buf)?;
        if num_bytes > MTU {
            return Err(Error::new(ErrorKind::Other, "received too many bytes."));
        }
        payload.len = num_bytes;
        Ok((src_addr, payload))
    }
}
