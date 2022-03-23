use crate::protocol::network::{IPPacket, NetworkInterface, RIP_PROTOCOL};
use byteorder::*;
use std::cmp::min;
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
 * - next_hop: the remote IP address to the next node in the route
 * - gateway: local (gateway) IP address to the next node in the route
 * - cost: the cost to reach the destination
 * - changed: whether this route has been recently changed.
 */
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Route {
    pub dst_addr: Ipv4Addr,
    pub gateway: Ipv4Addr,
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

    pub fn has_dst(&self, dst_addr: &Ipv4Addr) -> bool {
        self.routes.contains_key(dst_addr)
    }

    pub fn get_route(&self, dst_addr: &Ipv4Addr) -> Route {
        self.routes[dst_addr]
    }

    pub fn insert(&mut self, route: Route) {
        self.routes.insert(route.dst_addr, route);
    }

    pub fn delete(&mut self, dst_addr: &Ipv4Addr) {
        self.routes.remove_entry(dst_addr);
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
    /*
     * Dummy route for initial RIP request.
     */
    // pub const DUMMY_ROUTE: RouteEntry = RouteEntry {
    // cost: INFINITY,
    // address: 0,
    // mask: INIT_MASK,
    // };

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
            // TODO: some issue with parsing multiple entries; payload isn't increasing
            let cost = payload.read_u32::<NetworkEndian>()?;
            let address = payload.read_u32::<NetworkEndian>()?;
            let mask = payload.read_u32::<NetworkEndian>()?;
            msg.entries.push(RouteEntry {
                cost,
                address,
                mask,
            });
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

pub fn validate_entry(entry: &RouteEntry) -> Result<()> {
    let ip_addr = Ipv4Addr::from(entry.address);
    // check if unicast
    if Ipv4Addr::is_unspecified(&ip_addr)
        || Ipv4Addr::is_multicast(&ip_addr)
        || Ipv4Addr::is_broadcast(&ip_addr)
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "must be unicast address!",
        ));
    }

    // validate cost
    // if entry.cost < 1 || entry.cost > 16 { // TODO: how to do this? RFC says if not [1, 16]
    if entry.cost > 16 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "cost must be between 1 and 16, inclusive",
        ));
    }

    Ok(())
}

/**
 * Find opposite IP address of a gateway IP address.
 */
fn get_end_addr(interfaces: &[NetworkInterface], gateway_addr: &Ipv4Addr) -> Option<Ipv4Addr> {
    let mut end_addr = None;

    for net_if in interfaces {
        if net_if.src_addr == *gateway_addr {
            end_addr = Some(net_if.dst_addr);
            break;
        }
    }

    end_addr
}

/**
 * Converts a route in the RoutingTable into a RouteEntry for RIPMessages.
 */
pub fn process_route(
    src_addr: &Ipv4Addr,
    dst_addr: &Ipv4Addr,
    route: &Route,
) -> Result<RouteEntry> {
    // here next hop is the REMOTE VIRTUAL IP ADDRESS of the interface
    // if next hop is same as source, poison it
    let cost = if route.next_hop == *src_addr {
        INFINITY
    } else {
        route.cost as u32
    };

    // turn entry into route
    Ok(RouteEntry {
        cost,
        address: u32::from_be_bytes(dst_addr.octets()),
        mask: route.mask,
    })
}

pub fn make_rip_handler(
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let interfaces = interfaces.lock().unwrap();

        // get source (opposite IP) and gateway IP address (this is the destination of the packet!)
        let source_addr = Ipv4Addr::from(packet.header.source);
        let gateway_addr = Ipv4Addr::from(packet.header.destination);

        println!("Source: {}\tGateway: {}", source_addr, gateway_addr);

        // check that source addr is one of the destination interfaces
        let src_if_index = in_interfaces(&source_addr, &*interfaces);
        if src_if_index < 0 {
            return Err(Error::new(
                ErrorKind::Other,
                "Source address not from directly connected neighbor!",
            ));
        }
        let src_if_index = src_if_index as usize;

        // first, attempt to parse into rip message; validates that protocol is right
        let msg = recv_rip_message(&packet)?;

        println!("RIP Message: {:?}", msg);

        // Handle Request
        if msg.command == RIP_REQUEST {
            match msg.num_entries {
                // if no entries, send response
                0 => {
                    // TODO: this is how the RFC does it...
                    // if msg.entries[0] != RouteEntry::DUMMY_ROUTE {
                    // return Err(Error::new(
                    // ErrorKind::Other,
                    // "RIP requests must have 1 entry with a default route.",
                    // ));
                    // }

                    let routing_table = routing_table.lock().unwrap();
                    // for each entry in the routing table, add to RIP message
                    let mut entries: Vec<RouteEntry> =
                        Vec::<RouteEntry>::with_capacity(routing_table.size());

                    // for each route, process it (SH w/ PR) then add to entries
                    for (dst_addr, route) in routing_table.iter() {
                        let route_entry = process_route(&source_addr, dst_addr, route)?;
                        entries.push(route_entry);
                    }

                    // make new RIP message
                    let msg = RIPMessage {
                        command: RIP_RESPONSE,
                        num_entries: entries.len() as u16,
                        entries,
                    };

                    // send message response!
                    return send_rip_message(&interfaces[src_if_index], msg);
                }
                // if more than 0 entries, do nothing
                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "RIP requests with more than 1 entry are not currently supported.",
                    ))
                }
            }
        } else if msg.command == RIP_RESPONSE {
            let mut routing_table = routing_table.lock().unwrap();
            // for each entry in the routing table, add to RIP message
            // let mut entries: Vec<RouteEntry> =
            // Vec::<RouteEntry>::with_capacity(routing_table.size());

            // process each entry
            for entry in msg.entries {
                // first, validate each entry
                match validate_entry(&entry) {
                    Ok(_) => println!("Current entry: {:?}", entry),
                    Err(e) => {
                        println!("{}", e);
                        continue;
                    }
                }
                // final destination address of this entry
                let dst_addr = Ipv4Addr::from(entry.address);
                // if valid, update metric
                let new_metric = min(entry.cost + 1, INFINITY);

                // if no explicit route:
                if !routing_table.has_dst(&dst_addr) {
                    // if not infinity, add to routing table
                    if new_metric < INFINITY {
                        let new_route = Route {
                            dst_addr,
                            gateway: gateway_addr,
                            next_hop: source_addr,
                            cost: new_metric,
                            changed: true,
                            mask: INIT_MASK,
                        };
                        routing_table.insert(new_route);
                    }
                } else {
                    let mut route = routing_table.get_route(&dst_addr);
                    // otherwise, if (metrics diff and E's src addr == next hop addr) OR (new
                    // metric < curr metric)
                    if (new_metric != route.cost && route.next_hop == source_addr)
                        || (new_metric < route.cost)
                    {
                        // set metric, and update next hop
                        route.cost = new_metric;
                        route.next_hop = source_addr;
                        // mark as changed
                        route.changed = true;

                        // if metric is infinity, delete from table
                        if new_metric == INFINITY {
                            // TODO: figure out deletion steps
                        } else {
                            // otherwise, update routing table
                            routing_table.insert(route);
                        }
                    }
                }
            }

            println!("\n");
        }

        Ok(())
    }))
}
