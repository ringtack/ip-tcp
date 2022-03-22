use std::io::{self, Error, ErrorKind};
use std::net;

pub const MTU: usize = 1400;

// TODO: implement Clone
pub struct LinkInterface {
    socket: net::UdpSocket,
    socket_addr: net::SocketAddrV4,
    active: bool,
}

impl Clone for LinkInterface {
    fn clone(&self) -> Self {
        LinkInterface {
            socket: self.socket.try_clone().unwrap(),
            socket_addr: self.socket_addr,
            active: self.active,
        }
    }
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
        dest_link: &LinkInterface,
        payload: [u8; MTU],
    ) -> Result<usize, io::Error> {
        if !self.active {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "sending to unreachable address",
            ));
        }
        self.socket.send_to(&payload, dest_link.socket_addr)
    }

    pub fn recv_link_frame(&self) -> Result<(net::SocketAddr, [u8; MTU]), Error> {
        if !self.active {
            return Err(Error::new(ErrorKind::NotConnected, "Link is down."));
        }
        let mut payload: [u8; MTU] = [0; MTU];
        let (num_bytes, src_addr) = self.socket.recv_from(&mut payload)?;
        if num_bytes > MTU {
            return Err(Error::new(ErrorKind::Other, "received too many bytes."));
        }
        Ok((src_addr, payload))
    }
}
