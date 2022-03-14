mod rip;
use super::link::{LinkInterface, LinkPayload};
use etherparse::Ipv4Header;
use std::io::{Error, ErrorKind};
use std::net;

pub struct NetworkInterface {
    id: u8,
    src_addr: net::Ipv4Addr,
    dst_addr: net::Ipv4Addr,
    dst_link: LinkInterface,
}

impl NetworkInterface {
    pub fn new(
        id: u8,
        src_addr: net::Ipv4Addr,
        dst_addr: net::Ipv4Addr,
        sock_addr: net::SocketAddrV4,
    ) -> Result<NetworkInterface, Error> {
        let net_if = NetworkInterface {
            id,
            src_addr,
            dst_addr,
            dst_link: LinkInterface::new(sock_addr)?,
        };
        Ok(net_if)
    }
}

pub struct IPPacket {
    header: Ipv4Header,
    payload: Vec<u8>, // how to make VLA in Rust?
}

impl IPPacket {
    pub fn new() {
        // TODO: learn how to convert header + payload into bytes
    }
}
