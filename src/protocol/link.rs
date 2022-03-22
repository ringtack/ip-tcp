use std::io::{self, Error, ErrorKind};
use std::net;

pub const MTU: usize = 1400;

/**
 * Struct representing a Link Interface.
 *
 * Fields:
 * - socket: UDP Socket abstraction representing the link
 * - socket_addr: Address of socket abstraction
 * - active: whether link interface is on or off
 */
pub struct LinkInterface {
    socket: net::UdpSocket,
    socket_addr: net::SocketAddrV4,
    pub active: bool,
}

/**
 * Allow for cloning the link interface. socket should be unchanged.
 */
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
    /**
     * Creates a new link interface, given a socket address.
     */
    pub fn new(socket_addr: net::SocketAddrV4) -> Result<LinkInterface, Error> {
        let link_interface = LinkInterface {
            socket: net::UdpSocket::bind(socket_addr)?,
            socket_addr,
            active: true,
        };
        Ok(link_interface)
    }

    /**
     * Enables the link interface.
     */
    pub fn link_up(&mut self) {
        self.active = true;
    }

    /**
     * Enables the link interface.
     */
    pub fn link_down(&mut self) {
        self.active = false;
    }

    /**
     * Sends a link frame to the destination link interface.
     *
     * Inputs:
     * - dst_link: the target link interface.
     * - payload: payload of the L2 frame. Size must be < MTU.
     *
     * Returns:
     * - A Result<usize, Error> of the number of bytes sent, or an error
     */
    pub fn send_link_frame(
        &self,
        dst_link: &LinkInterface,
        payload: &[u8],
    ) -> Result<usize, Error> {
        // if either current or dest link is down, don't send
        if !self.active || !dst_link.active {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "sending to unreachable address",
            ));
        }
        // if payload larger than MTU, don't send
        if payload.len() > MTU {
            return Err(Error::new(ErrorKind::InvalidData, "payload too large"));
        }
        self.socket.send_to(payload, dst_link.socket_addr)
    }

    /**
     * Receives a link frame.
     *
     * Returns:
     * - A Result<(net::SocketAddr, [u8; MTU]), Error> of the source socket addr and payload, or an
     * error
     */
    pub fn recv_link_frame(&self, payload: &mut [u8; MTU]) -> Result<net::SocketAddr, Error> {
        // if locally not active, return an error
        if !self.active {
            return Err(Error::new(ErrorKind::NotConnected, "Link is down."));
        }
        // store payload
        let (num_bytes, src_addr) = self.socket.recv_from(payload)?;
        // if read more than MTU, return error
        if num_bytes > MTU {
            return Err(Error::new(ErrorKind::Other, "received too many bytes."));
        }
        Ok(src_addr)
    }
}
