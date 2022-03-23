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
 * - dst_addr: the IP address of the dest IF.
 * - link_if: the link interface of the destination.
 */
#[derive(Clone)]
pub struct NetworkInterface {
    pub id: u8,
    pub src_addr: net::Ipv4Addr,
    pub dst_addr: net::Ipv4Addr,
    pub link_if: LinkInterface,
}

/**
 * IP Packet.
 */
pub struct IPPacket {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
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
    /**
     * Creates a new Network Interface.
     *
     * Inputs:
     * - id: unique id
     * - src_addr: IP address of source IF
     * - dst_addr: IP address of dest IF
     * - src_sock: UdpSocket of source link. Used with dst_link to make LinkInterface.
     * - dst_link: SocketAddrV4 of dst link
     */
    pub fn new(
        id: u8,
        src_addr: net::Ipv4Addr,
        dst_addr: net::Ipv4Addr,
        src_sock: &net::UdpSocket,
        dst_link: net::SocketAddrV4,
    ) -> Result<NetworkInterface, Error> {
        let net_if = NetworkInterface {
            id,
            src_addr,
            dst_addr,
            link_if: LinkInterface::new(src_sock, dst_link)?,
        };
        Ok(net_if)
    }

    /**
     * Sends an IP packet with the given payload.
     *
     * Inputs:
     * - payload: payload of bytes to send.
     * - protocol: which IP protocol to use (0: Test, 200: RIP, more to come)
     *
     * Returns:
     * - Whether operation was successful or not
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

        self.link_if.send_link_frame(payload.as_slice())?;
        Ok(())
    }

    /**
     * Receives an IP Packet.
     *
     * Returns:
     * - A Result<IPPacket, Error> with the received IP packet, or an error
     */
    pub fn recv_ip(&self) -> Result<IPPacket, Error> {
        let mut buf: [u8; MTU] = [0; MTU];
        // get L2 payload
        let (num_bytes, _) = self.link_if.recv_link_frame(&mut buf)?;
        // custom handling (since from_slice gives a weird error :/)
        match Ipv4Header::from_slice(&buf) {
            Ok((header, buf)) => {
                // TODO: validation

                // get IP payload from L2 payload
                let mut payload = Vec::<u8>::with_capacity(num_bytes);
                payload.extend_from_slice(&buf[..num_bytes]);
                // return packet
                Ok(IPPacket { header, payload })
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }
}
