pub mod rip;
use crate::protocol::link::{LinkInterface, MTU};
use crate::protocol::network::rip::DEFAULT_TTL;
use etherparse::{IpNumber, Ipv4Header};
use std::{io::Error, mem, net, slice};

pub struct NetworkInterface {
    pub id: u8,
    pub src_addr: net::Ipv4Addr,
    pub src_link: LinkInterface,
    pub dst_addr: net::Ipv4Addr,
    pub dst_link: LinkInterface,
}

pub struct IPPacket<'a> {
    header: Ipv4Header,
    payload: &'a [u8], // how to make VLA in Rust?
}

impl<'a> IPPacket<'a> {
    pub fn new(net_if: &NetworkInterface, payload: &'a [u8], ttl: u8) -> IPPacket<'a> {
        IPPacket {
            header: Ipv4Header::new(
                payload.len() as u16,
                ttl,
                IpNumber::ExperimentalAndTesting0, // IpNumber::from(200 as u8), // TODO: how to fix this?
                net_if.src_addr.octets(),
                net_if.dst_addr.octets(),
            ),
            payload,
        }
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

    pub fn send_ip(&self, payload: &[u8]) -> Result<(), Error> {
        // make packet
        let packet = IPPacket::new(self, payload, DEFAULT_TTL);
        // obtain raw pointer to data
        let p: *const IPPacket = &packet;
        // convert between pointer types (to u8)
        let p: *const u8 = p as *const u8;
        // interpret as slice
        let payload: &[u8] = unsafe { slice::from_raw_parts(p, mem::size_of::<IPPacket>()) };
        let mut buf = [0; MTU];
        buf.copy_from_slice(payload);
        // convert packet to link level payload, then send
        self.src_link.send_link_frame(&self.dst_link, buf)?;
        Ok(())
    }
}
