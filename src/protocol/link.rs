use std::io::{Error, ErrorKind};
use std::net::{SocketAddr::*, SocketAddrV4, UdpSocket};

pub const MTU: usize = 1400;

/**
 * Struct representing a Link Interface.
 *
 * Fields:
 * - src_link: UDP Socket abstraction representing the SOURCE LINK
 * - dst_link_addr: "L2" (aka socket) address representing the DESTINATION LINK ADDRESS
 * - active: whether link interface is on or off
 */
pub struct LinkInterface {
    src_link: UdpSocket,         // SOURCE SOCKET
    dst_link_addr: SocketAddrV4, // DESTINATION ADDRESS
    pub active: bool,
}

/**
 * Allow for cloning the link interface. socket should be unchanged.
 */
impl Clone for LinkInterface {
    fn clone(&self) -> Self {
        LinkInterface {
            src_link: self.src_link.try_clone().unwrap(),
            dst_link_addr: self.dst_link_addr,
            active: self.active,
        }
    }
}

impl LinkInterface {
    /**
     * Creates a new link interface, given a socket address.
     */
    // pub fn new(socket_addr: SocketAddrV4) -> Result<LinkInterface, Error> {
    // println!("Binding to {}...", socket_addr);
    // let link_interface = LinkInterface {
    // socket: UdpSocket::bind(socket_addr)?,
    // socket_addr,
    // active: true,
    // };
    // Ok(link_interface)
    // }

    /**
     * Creates a new link interface from a given source socket (SOURCE LINK) and socket address
     * (DESTINATION LINK ADDR).
     */
    pub fn new(src_link: &UdpSocket, dst_addr: SocketAddrV4) -> Result<LinkInterface, Error> {
        let src_link = src_link.try_clone()?;
        Ok(LinkInterface {
            src_link,
            dst_link_addr: dst_addr,
            active: true,
        })
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
        // dst_link: &LinkInterface,
        payload: &[u8],
    ) -> Result<usize, Error> {
        // if either current or dest link is down, don't send
        if !self.active {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "sending to unreachable address",
            ));
        }
        // if payload larger than MTU, don't send
        if payload.len() > MTU {
            return Err(Error::new(ErrorKind::InvalidData, "payload too large"));
        }

        println!("Sending frame to {}...", self.dst_link_addr);

        self.src_link.send_to(payload, self.dst_link_addr)
    }

    /**
     * Receives a link frame.
     *
     * Returns:
     * - A Result<(net::SocketAddr, [u8; MTU]), Error> of the source socket addr and payload, or an
     * error
     */
    pub fn recv_link_frame(&self, payload: &mut [u8; MTU]) -> Result<(usize, SocketAddrV4), Error> {
        // if locally not active, return an error
        if !self.active {
            return Err(Error::new(ErrorKind::NotConnected, "Link is down."));
        }
        // store payload
        let (num_bytes, src_addr) = self.src_link.recv_from(payload)?;
        // if read more than MTU, return error
        if num_bytes > MTU {
            return Err(Error::new(ErrorKind::Other, "received too many bytes."));
        }
        // coerce into SocketAddrV4
        let src_addr = match src_addr {
            V4(addr) => addr,
            V6(_) => return Err(Error::new(ErrorKind::Other, "IPv6 not supported!")),
        };
        Ok((num_bytes, src_addr))
    }
}
