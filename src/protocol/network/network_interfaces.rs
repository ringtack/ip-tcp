use crate::protocol::{link::*, network::*};
use std::{
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    slice::Iter,
    sync::atomic::Ordering,
};

/**
 * Collection of network interfaces for a single node.
 *
 * Fields:
 * - interfaces: vector of Network Interfaces
 */
pub struct NetworkInterfaces {
    interfaces: Vec<NetworkInterface>,
}

impl NetworkInterfaces {
    /**
     * Create an empty NetworkInterfaces struct to fill in.
     */
    pub fn new() -> NetworkInterfaces {
        NetworkInterfaces {
            interfaces: Vec::new(),
        }
    }

    /**
     * Insert a NetworkInterface into the collection.
     *
     * Inputs:
     * - net_if: the new network interface.
     */
    pub fn insert(&mut self, net_if: NetworkInterface) {
        self.interfaces.push(net_if);
    }

    /**
     * Get an unspecified network interface from the list.
     */
    pub fn get_net_if(&self) -> NetworkInterface {
        self.interfaces[0].clone()
    }

    /**
     * Checks if an address is the destination address of an immediate neighbor.
     * Gets the network interface of the specified immediate neighbor, if possible.
     *
     * Inputs:
     * - addr: the neighbor address
     *
     * Returns:
     * - Some(net_if) if a local interface is found, None otherwise
     */
    pub fn get_neighbor_if(&self, addr: &Ipv4Addr) -> Option<&NetworkInterface> {
        for net_if in &self.interfaces {
            if *addr == net_if.dst_addr {
                return Some(net_if);
            }
        }

        None
    }

    /**
     * Checks if a gateway address is a local interface.
     *
     * Inputs:
     * - gateway_addr: the gateway addr of the local interface.
     *
     * Returns:
     * - true if a local interface has gateway_addr as its source, false otherwise
     */
    pub fn is_local_if(&self, gateway_addr: &Ipv4Addr) -> bool {
        self.interfaces
            .iter()
            .any(|net_if| net_if.src_addr == *gateway_addr)
    }

    /**
     * Attempts to fetch a local interface with the specified gateway address.
     *
     * Inputs:
     * - gateway_addr: the gateway address of the local interface.
     *
     * Returns:
     * - Some(net_if) if a local interface is found, None otherwise
     */
    pub fn get_local_if(&self, gateway_addr: &Ipv4Addr) -> Option<&NetworkInterface> {
        for net_if in &self.interfaces {
            if net_if.src_addr == *gateway_addr {
                return Some(net_if);
            }
        }
        None
    }

    /**
     * Checks if link interface with immediate neighbor is active.
     *
     * Inputs:
     * - src_link_addr: the source socket address of the packet
     *
     * Returns:
     * - true if link interface is active, false otherwise
     */
    pub fn link_active(&self, src_link_addr: &SocketAddrV4) -> bool {
        for net_if in &self.interfaces {
            if net_if.link_if.dst_link_addr == *src_link_addr {
                return net_if.is_active();
            }
        }
        false
    }

    /**
     * Finds the interface with the specified id, if it exists.
     *
     * Inputs:
     * - id: the interface id
     *
     * Returns:
     * - a mutable NetworkInterface with the specified id, or an Error
     */
    pub fn find_interface_id(&self, id: isize) -> Result<NetworkInterface> {
        // check if is valid interface
        if id < 0 || id as usize >= self.interfaces.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "interface {} out of bounds : (0 to {})",
                    id,
                    self.interfaces.len()
                ),
            ));
        }

        // find interface we're bringing down
        for interface in &self.interfaces {
            if interface.id == id as u8 {
                return Ok(interface.clone());
            }
        }

        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("interface {} does not exist!", id),
        ))
    }

    /**
     * Converts network interfaces into a string to display on startup.
     */
    pub fn fmt_startup_interfaces(&self) -> String {
        let mut res = String::new();
        for (index, interface) in self.interfaces.iter().enumerate() {
            res.push_str(&(format!("{}:\t{}", interface.id, interface.src_addr)));
            if index != self.interfaces.len() - 1 {
                res.push('\n');
            }
        }
        res
    }

    /**
     * Converts network interfaces into a human-readable string.
     */
    pub fn fmt_interfaces(&self) -> String {
        let mut res = String::new();
        res.push_str("id\trem\t\tloc\n");
        for (index, interface) in self.interfaces.iter().enumerate() {
            if !interface.link_if.active.load(Ordering::Relaxed) {
                continue;
            }
            res.push_str(
                &(format!(
                    "{}\t{}\t{}",
                    interface.id, interface.dst_addr, interface.src_addr
                )),
            );
            if index != self.interfaces.len() - 1 {
                res.push('\n');
            }
        }
        res
    }

    pub fn iter(&self) -> Iter<NetworkInterface> {
        self.interfaces.iter()
    }
}

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
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub link_if: LinkInterface,
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
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_sock: &UdpSocket,
        dst_link: SocketAddrV4,
    ) -> Result<NetworkInterface> {
        let net_if = NetworkInterface {
            id,
            src_addr,
            dst_addr,
            link_if: LinkInterface::new(src_sock, dst_link)?,
        };
        Ok(net_if)
    }

    /**
     * Sends an IP packet.
     *
     * Inputs:
     * - packet: the packet to send
     *
     * Returns:
     * - Whether packet was successfully sent or not
     */
    pub fn send_packet(&self, packet: IPPacket) -> Result<()> {
        self.link_if
            .send_link_frame(packet.to_bytes()?.as_slice())?;
        Ok(())
    }

    /**
     * Sends an IP packet with the given payload.
     *
     * Inputs:
     * - payload: payload of bytes to send.
     * - protocol: which IP protocol to use (0: Test, 7: TCP, 200: RIP, more to come)
     *
     * Returns:
     * - Whether operation was successful or not
     */
    pub fn send_packet_raw(
        &self,
        payload: &[u8],
        protocol: u8,
        ttl: u8,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<()> {
        let mut buf = Vec::<u8>::with_capacity(payload.len());
        buf.extend_from_slice(payload);
        // make packet
        let packet = IPPacket::new(source, destination, buf, ttl, protocol);

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
    pub fn recv_packet(&self) -> Result<(IPPacket, SocketAddrV4)> {
        let mut buf: [u8; MTU] = [0; MTU];
        // get L2 payload
        let (num_bytes, src_addr) = self.link_if.recv_link_frame(&mut buf)?;
        match IPPacket::from_bytes(&buf, num_bytes) {
            Ok(packet) => Ok((packet, src_addr)),
            Err(e) => Err(e),
        }
    }

    /**
     * Checks if network interface is active.
     */
    pub fn is_active(&self) -> bool {
        self.link_if.active.load(Ordering::Relaxed)
    }
}
