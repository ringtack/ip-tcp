use crate::protocol::network::{IPPacket, NetworkInterface, RIP_PROTOCOL, TEST_PROTOCOL};
use byteorder::*;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

pub const MAX_ROUTES: usize = 64;
pub const DEFAULT_TTL: u8 = 16; // TODO: which value???
pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

pub const RIP_REQUEST: u16 = 1;
pub const RIP_RESPONSE: u16 = 2;

pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

/**
 * Struct representing a Route in the RoutingTable.
 *
 * Fields:
 * - dst_addr: the destination address
 * - next_hop: the next gateway
 * - cost: the cost to reach the destination
 * - changed: whether this route has been recently changed.
 */
#[derive(Hash, PartialEq, Eq)]
pub struct Route {
    pub dst_addr: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub cost: u32,
    pub changed: bool,
    pub mask: u32,
}

/**
 * Routing Table. Maps destination addresses to routes.
 */
pub struct RoutingTable {
    routes: HashMap<Ipv4Addr, Route>,
}

impl RoutingTable {
    pub fn new() -> RoutingTable {
        RoutingTable {
            routes: HashMap::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.routes.len()
    }

    pub fn insert(&mut self, route: Route) {
        self.routes.insert(route.dst_addr, route);
    }
    pub fn iter(&self) -> Iter<'_, Ipv4Addr, Route> {
        self.routes.iter()
    }
}

/**
 * Wrapper function to concurrently insert (update) route from routing table.
 */
pub fn insert_route(routing_table: Arc<Mutex<RoutingTable>>, route: Route) {
    let mut rt = routing_table.lock().unwrap();
    rt.insert(route);
}

/**
 * Struct representing a route entry in a RIP message.
 *
 * Fields:
 * - cost: cost to reach destination
 * - address: destination address
 * - mask: netmask; default is 255.255.255.255
 */
#[derive(Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub cost: u32,
    pub address: u32,
    pub mask: u32,
}

impl RouteEntry {
    /**
     * Dummy route for initial RIP request.
     */
    pub const DUMMY_ROUTE: RouteEntry = RouteEntry {
        cost: INFINITY,
        address: 0,
        mask: INIT_MASK,
    };

    /**
     * Converts RouteEntry into a vector of bytes.
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        // create byte vector of enough size
        let mut bytes = Vec::<u8>::with_capacity(mem::size_of::<u32>() * 3);

        // convert each field into bytes
        bytes.extend_from_slice(&u32::to_be_bytes(self.cost));
        bytes.extend_from_slice(&u32::to_be_bytes(self.address));
        bytes.extend_from_slice(&u32::to_be_bytes(self.mask));
        bytes
    }

    /**
     * Parses a slice of bytes into a RouteEntry.
     */
    pub fn from_bytes(mut payload: &[u8]) -> Result<RouteEntry> {
        let cost = payload.read_u32::<NetworkEndian>()?;
        let address = payload.read_u32::<NetworkEndian>()?;
        let mask = payload.read_u32::<NetworkEndian>()?;
        Ok(RouteEntry {
            cost,
            address,
            mask,
        })
    }
}

/**
 * RIP Message.
 *
 * Fields:
 * - command: either 1 (request) or 2 (response)
 * - num_entries: number of RouteEntries
 * - entries: vector of entries
 */
#[derive(Debug)]
pub struct RIPMessage {
    pub command: u16,
    pub num_entries: u16,
    pub entries: Vec<RouteEntry>,
}

impl RIPMessage {
    pub fn new(command: u16, num_entries: u16, entries: Vec<RouteEntry>) -> RIPMessage {
        RIPMessage {
            command,
            num_entries,
            entries,
        }
    }

    /**
     * Converts RIPMessage into a vector of bytes.
     */
    pub fn to_bytes(&self) -> Vec<u8> {
        // create bytes vector of the correct size
        let mut bytes: Vec<u8> = Vec::<u8>::with_capacity(
            mem::size_of::<u16>() * 2 + (mem::size_of::<u32>() * 3) * (self.num_entries as usize),
        );

        // appends bytes of command and num_entries
        bytes.extend_from_slice(&u16::to_be_bytes(self.command));
        bytes.extend_from_slice(&u16::to_be_bytes(self.num_entries));

        // for every entry, get byte representation and append to bytes
        // TODO: figure out how to do this all at once?
        for i in 0..self.num_entries {
            let entry_bytes = self.entries[i as usize].to_bytes();
            bytes.extend_from_slice(entry_bytes.as_slice());
        }

        bytes
    }

    /**
     * Converts a slice of bytes into a RIPMessage.
     */
    pub fn from_bytes(mut payload: &[u8]) -> Result<RIPMessage> {
        let command = payload.read_u16::<NetworkEndian>()?;
        let num_entries = payload.read_u16::<NetworkEndian>()?;

        let mut msg = RIPMessage {
            command,
            num_entries,
            entries: Vec::with_capacity(num_entries as usize),
        };

        for _ in 0..num_entries {
            msg.entries.push(RouteEntry::from_bytes(payload)?);
        }

        Ok(msg)
    }
}

/**
 * Sends a RIP message to the specified destination interface.
 *
 * Inputs:
 * - dest_if: where to send RIP message
 * - msg: the RIP message
 *
 * Returns:
 * - A Result<(), Error> with nothing, or an error
 */
pub fn send_rip_message(dest_if: &NetworkInterface, msg: RIPMessage) -> Result<()> {
    let payload = msg.to_bytes();
    dest_if.send_ip(payload.as_slice(), RIP_PROTOCOL)
}

/**
 * Parses a RIP Message from a packet.
 */
pub fn recv_rip_message(packet: &IPPacket) -> Result<RIPMessage> {
    // Validate appropriate protocol
    if packet.header.protocol != RIP_PROTOCOL {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid protocol! Must be 200 (RIP).",
        ));
    }

    // create RIP message
    let msg = RIPMessage::from_bytes(packet.payload.as_slice())?;
    // validate command
    if msg.command != RIP_REQUEST && msg.command != RIP_RESPONSE {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid command! Must be 1 (request) or 2 (response)",
        ));
    }

    Ok(msg)
}

pub fn in_interfaces(addr: &Ipv4Addr, interfaces: &[NetworkInterface]) -> isize {
    let mut in_ifs = -1;

    for (i, net_if) in interfaces.iter().enumerate() {
        if net_if.dst_addr == *addr {
            in_ifs = i as isize;
            break;
        }
    }

    in_ifs
}

pub fn make_rip_handler(
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let interfaces = Arc::clone(&interfaces);
        let interfaces = interfaces.lock().unwrap();

        // get source IP address
        let src_addr = Ipv4Addr::from(packet.header.source);

        println!("In RIP handler; packet from {}...", src_addr);

        // check that source addr is one of the destination addresses
        let src_if_index = in_interfaces(&src_addr, &*interfaces);

        println!("src if index: {}", src_if_index);

        if src_if_index < 0 {
            return Err(Error::new(
                ErrorKind::Other,
                "Source address not from reachable interface!",
            ));
        }
        let src_if_index = src_if_index as usize;

        // first, attempt to parse into rip message
        let msg = recv_rip_message(&packet)?;

        println!("RIP Message: {:?}", msg);

        // Handle Request
        if msg.command == RIP_REQUEST {
            match msg.num_entries {
                // if no entries, do nothing
                0 => return Ok(()),
                // if 1 entry, check that entry is default
                1 => {
                    if msg.entries[0] != RouteEntry::DUMMY_ROUTE {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "RIP requests must have 1 entry with a default route.",
                        ));
                    }

                    println!("in here 1");

                    let routing_table = routing_table.lock().unwrap();
                    // for each entry in the routing table, add to RIP message
                    let mut entries: Vec<RouteEntry> =
                        Vec::<RouteEntry>::with_capacity(routing_table.size());
                    for (dst_addr, entry) in routing_table.iter() {
                        println!("in here 2");

                        // if next hop is same as source, poison it
                        let cost = if entry.next_hop == src_addr {
                            INFINITY
                        } else {
                            entry.cost as u32
                        };

                        // turn entry into route
                        let route_entry = RouteEntry {
                            cost,
                            address: u32::from_be_bytes(dst_addr.octets()),
                            mask: entry.mask,
                        };

                        entries.push(route_entry);
                    }
                    // make new RIP message
                    let msg = RIPMessage {
                        command: RIP_RESPONSE,
                        num_entries: entries.len() as u16,
                        entries,
                    };

                    println!("Sending {:?}...", msg);

                    // send message response!
                    return send_rip_message(&interfaces[src_if_index], msg);
                }
                // if more than 1 entry, do nothing
                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "RIP requests with more than 1 entry are not currently supported.",
                    ))
                }
            }
        } else if msg.command == RIP_RESPONSE {
            return Ok(());
        }

        Ok(())
    }))
}
// pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

// pub fn rip_handler(packet: IPPacket) -> Result<(), Error> {
// // get source IP address
// let src_addr = Ipv4Addr::from(packet.header.source);

// println!("In RIP handler; packet from {}...", src_addr);

// let node = node.lock().unwrap();
// // check that source addr is one of the destination addresses
// let src_if_index = in_interfaces(&src_addr, &node.interfaces);

// println!("src if index: {}", src_if_index);

// if src_if_index < 0 {
// return Err(Error::new(
// ErrorKind::Other,
// "Source address not from reachable interface!",
// ));
// }
// let src_if_index = src_if_index as usize;

// // first, attempt to parse into rip message
// let msg = recv_rip_message(&packet)?;

// println!("RIP Message: {:?}", msg);

// // Handle Request
// if msg.command == RIP_REQUEST {
// match msg.num_entries {
// // if no entries, do nothing
// 0 => return Ok(()),
// // if 1 entry, check that entry is default
// 1 => {
// if msg.entries[0] != RouteEntry::DUMMY_ROUTE {
// return Err(Error::new(
// ErrorKind::Other,
// "RIP requests must have 1 entry with a default route.",
// ));
// }

// println!("in here 1");

// // for each entry in the routing table, add to RIP message
// let mut entries: Vec<RouteEntry> =
// Vec::<RouteEntry>::with_capacity(node.routing_table.size());
// for (dst_addr, entry) in node.routing_table.iter() {
// println!("in here 2");

// // if next hop is same as source, poison it
// let cost = if entry.next_hop == src_addr {
// INFINITY
// } else {
// entry.cost as u32
// };

// // turn entry into route
// let route_entry = RouteEntry {
// cost,
// address: u32::from_be_bytes(dst_addr.octets()),
// mask: entry.mask,
// };

// entries.push(route_entry);
// }
// // make new RIP message
// let msg = RIPMessage {
// command: RIP_RESPONSE,
// num_entries: entries.len() as u16,
// entries,
// };

// println!("Sending {:?}...", msg);

// // send message response!
// return send_rip_message(&node.interfaces[src_if_index], msg);
// }
// // if more than 1 entry, do nothing
// _ => {
// return Err(Error::new(
// ErrorKind::Other,
// "RIP requests with more than 1 entry are not currently supported.",
// ))
// }
// }
// } else if msg.command == RIP_RESPONSE {
// return Ok(());
// }

// Ok(())
// }
