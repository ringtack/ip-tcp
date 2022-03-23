pub mod rip;
use crate::protocol::link::{LinkInterface, MTU};
use crate::protocol::network::rip::DEFAULT_TTL;
use etherparse::{IpNumber, Ipv4Header};
use std::{
    io::{Error, ErrorKind},
    net,
};

pub const TEST_PROTOCOL: u8 = 0;
pub const RIP_PROTOCOL: u8 = 200;

/**
 * Struct representing a single network interface.
 *
 * Fields:
 * - id: the unique ID of this IF.
 * - src_addr: the IP address of the source IF.
 * - src_link: reference to the Node's link interface. SHOULD NOT CHANGE!
 * - dst_addr: the IP address of the dest IF.
 * - dst_link: the link interface of the destination.
 */
pub struct NetworkInterface {
    pub id: u8,
    pub src_addr: net::Ipv4Addr,
    pub src_link: LinkInterface,
    pub dst_addr: net::Ipv4Addr,
    pub dst_link: LinkInterface,
}

/**
 * IP Packet.
 */
pub struct IPPacket {
    header: Ipv4Header,
    payload: Vec<u8>,
}

impl IPPacket {
    /**
     * Creates a new IP packet.
     *
     * Inputs:
     * - net_if: The NetworkInterface on which the packet will be sent
     * - payload: the payload of the packet
     * - ttl: time to live (usually default = 16)
     *
     * Returns:
     * - an IP Packet!
     */
    pub fn new(net_if: &NetworkInterface, payload: Vec<u8>, ttl: u8, protocol: u8) -> IPPacket {
        let mut packet = IPPacket {
            header: Ipv4Header::new(
                payload.len() as u16,
                ttl,
                IpNumber::IPv4, // dummy value, set later
                net_if.src_addr.octets(),
                net_if.dst_addr.octets(),
            ),
            payload,
        };
        // set protocol to specified protocol (test: 0, or RIP: 200)
        packet.header.protocol = protocol;
        // set checksum
        packet.header.header_checksum = packet.header.calc_header_checksum().unwrap();

        packet
    }
}

impl NetworkInterface {
    pub fn new(
        id: u8,
        src_addr: net::Ipv4Addr,
        src_link: LinkInterface,
        dst_addr: net::Ipv4Addr,
        sock_addr: net::SocketAddrV4,
    ) -> Result<NetworkInterface, Error> {
        let net_if = NetworkInterface {
            id,
            src_addr,
            src_link,
            dst_addr,
            dst_link: LinkInterface::new(sock_addr)?,
        };
        Ok(net_if)
    }

    /**
     * Sends an IP packet with the given payload.
     */
    pub fn send_ip(&self, payload: &[u8], protocol: u8) -> Result<(), Error> {
        let mut buf = Vec::<u8>::with_capacity(payload.len());
        buf.extend_from_slice(payload);
        // make packet
        let packet = IPPacket::new(self, buf, DEFAULT_TTL, protocol);

        // convert packet into bytes
        let mut header_bytes = Vec::<u8>::with_capacity(packet.header.header_len());
        // need custom check to convert to correct error type
        if let Err(e) = packet.header.write(&mut header_bytes) {
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }

        // combine into payload, and send
        let payload = [header_bytes.as_slice(), payload].concat();
        self.src_link
            .send_link_frame(&self.dst_link, payload.as_slice())?;
        Ok(())
    }

    /*
     * Receives an IP Packet.
     */
    pub fn recv_ip(&self) -> Result<IPPacket, Error> {
        let mut buf: [u8; MTU] = [0; MTU];
        let (num_bytes, _) = self.src_link.recv_link_frame(&mut buf)?;
        match Ipv4Header::from_slice(&buf) {
            Ok((header, buf)) => {
                let mut payload = Vec::<u8>::with_capacity(num_bytes);
                payload.extend_from_slice(&buf[..num_bytes]);
                Ok(IPPacket { header, payload })
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }
}
