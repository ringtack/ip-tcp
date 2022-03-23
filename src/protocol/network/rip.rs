use crate::protocol::network::{IPPacket, NetworkInterface, RIP_PROTOCOL, TEST_PROTOCOL};
use byteorder::*;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::mem;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

pub const MAX_ROUTES: usize = 64;
pub const DEFAULT_TTL: u8 = 16; // TODO: which value???
pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

pub const RIP_REQUEST: u16 = 1;
pub const RIP_RESPONSE: u16 = 2;

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
    pub cost: usize,
    pub changed: bool,
}

/**
 * Routing Table. Maps destination addresses to routes.
 */
pub struct RoutingTable {
    routes: HashMap<Ipv4Addr, Route>,
    // add synchronization primitives
}

impl RoutingTable {
    pub fn new() -> RoutingTable {
        RoutingTable {
            routes: HashMap::new(),
        }
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
#[derive(Debug, Clone)]
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

    pub fn new(cost: u32, address: u32) -> RouteEntry {
        RouteEntry {
            cost: cost,
            address: address,
            mask: INIT_MASK,
        }
    }

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
    pub fn from_bytes(mut payload: &[u8]) -> Result<RouteEntry, Error> {
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
#[derive(Debug, Clone)]
pub struct RIPMessage {
    command: u16,
    num_entries: u16,
    entries: Vec<RouteEntry>,
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
    pub fn from_bytes(mut payload: &[u8]) -> Result<RIPMessage, Error> {
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
pub fn send_rip_message(dest_if: &NetworkInterface, msg: RIPMessage) -> Result<(), Error> {
    let payload = msg.to_bytes();
    dest_if.send_ip(payload.as_slice(), RIP_PROTOCOL)
}

/**
 * Parses a RIP Message from a packet.
 */
pub fn recv_rip_message(packet: &IPPacket) -> Result<RIPMessage, Error> {
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
