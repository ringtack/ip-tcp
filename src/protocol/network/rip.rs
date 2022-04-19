use crate::protocol::network::{
    ip_packet::IPPacket,
    network_interfaces::*,
    routing_table::{Route, RoutingTable, ROUTE_TIMEOUT},
    Handler,
};

use byteorder::*;

use std::{
    cmp::min,
    collections::HashSet,
    fmt::{self, Display},
    io::{Error, ErrorKind, Result},
    mem,
    net::Ipv4Addr,
    sync::{mpsc::Sender, Arc, Mutex},
    time::{Duration, Instant},
};

pub const DEFAULT_TTL: u8 = 16;
pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

pub const RIP_PROTOCOL: u8 = 200;
pub const RIP_REQUEST: u16 = 1;
pub const RIP_RESPONSE: u16 = 2;

pub const UPDATE_TIME: u64 = 5;

/**
 * Struct representing a route entry in a RIP message.
 *
 * Fields:
 * - cost: cost to reach destination
 * - address: destination address
 * - mask: netmask; default is 255.255.255.255
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub cost: u32,
    pub address: u32,
    pub mask: u32,
}

impl Display for RouteEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Cost: {}, Address: {}, Mask: {}]",
            self.cost,
            Ipv4Addr::from(self.address),
            Ipv4Addr::from(self.mask)
        )
    }
}

impl RouteEntry {
    /**
     * Converts a list of updated Routes into RouteEntries, subject to SH w/ PR. Accumulates routes
     * that should be deleted.
     *
     * Inputs:
     * - updated_routes: a list of updated Routes
     * - to_delete: hash set in which to accumulate deleted routes
     * - net_if: network interface for SH w/ PR
     *
     * Returns:
     * - Processed list of route entries
     */
    pub fn process_updates(
        updated_routes: &[Route],
        to_delete: &mut HashSet<Ipv4Addr>,
        net_if: &NetworkInterface,
    ) -> Vec<RouteEntry> {
        let mut entries = Vec::with_capacity(updated_routes.len());
        for route in updated_routes {
            // if metric is infinity, add to deletions
            if route.cost == INFINITY {
                to_delete.insert(route.dst_addr);
            }
            // otherwise, SH w/ PR it
            let route_entry = RouteEntry::process_route(route, &net_if.dst_addr);
            // if not INFINITY, but SH w/ PR makes it so, don't send
            if route.cost == INFINITY || route_entry.cost != INFINITY {
                entries.push(route_entry)
            }
        }
        entries
    }

    /**
     * Converts a list of Routes into a list of processed RouteEntries.
     *
     * Inputs:
     * - routes: a list of routes to process
     * - net_if: the network interface for the SH w/ PR
     *
     * Returns:
     * - a list of route entries, post processing with the specified interface.
     */
    pub fn process_routes(routes: Vec<Route>, net_if: &NetworkInterface) -> Vec<RouteEntry> {
        routes
            .iter()
            .map(|route| RouteEntry::process_route(route, &net_if.dst_addr))
            .collect()
    }

    /**
     * Converts a Route into a RouteEntry.
     *
     * Inputs:
     * - remote_addr: the remote address of an interface. Compare with route.next_hop for SH w/ PR.
     * - route: the route to process
     *
     * Returns:
     * - A Result<RouteEntry> with the processed route entry, or an error
     */
    pub fn process_route(route: &Route, remote_addr: &Ipv4Addr) -> RouteEntry {
        // here next hop is the REMOTE VIRTUAL IP ADDRESS of the interface
        // if next hop is same as source, poison it
        let cost = if route.next_hop == *remote_addr {
            INFINITY
        } else {
            route.cost as u32
        };

        // turn entry into route
        RouteEntry {
            cost,
            address: u32::from_be_bytes(route.dst_addr.octets()),
            mask: route.mask,
        }
    }

    /**
     * Validate entry's correctness, according to the RFC.
     */
    fn validate_entry(&self) -> Result<()> {
        let ip_addr = Ipv4Addr::from(self.address);
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
        if self.cost > 16 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "cost must be between 0 and 16, inclusive",
            ));
        }

        Ok(())
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

    /*
     * Parses a slice of bytes into a RouteEntry.
     */
    // pub fn from_bytes(mut payload: &[u8]) -> Result<RouteEntry> {
    // let cost = payload.read_u32::<NetworkEndian>()?;
    // let address = payload.read_u32::<NetworkEndian>()?;
    // let mask = payload.read_u32::<NetworkEndian>()?;
    // Ok(RouteEntry {
    // cost,
    // address,
    // mask,
    // })
    // }
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
    pub command: u16,
    pub num_entries: u16,
    pub entries: Vec<RouteEntry>,
}

impl Display for RIPMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // collect entries
        let mut entries_str = String::new();
        for entry in &self.entries {
            entries_str.push_str(&entry.to_string());
        }

        write!(
            f,
            "[Command: {}, Num Entries: {}, Entries: {{{}}}]",
            self.command, self.num_entries, entries_str
        )
    }
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
 * Sends routes to the specified destination interface.
 *
 * Inputs:
 * - routes: the routes to send, pre-processed
 * - dest_if: the destination interface
 *
 * Returns:
 * - A Result<()> if successful, Err otherwise
 */
pub fn send_routes(routes: Vec<Route>, dest_if: &NetworkInterface) -> Result<()> {
    let route_entries = RouteEntry::process_routes(routes, dest_if);
    send_route_entries(route_entries, dest_if);
    Ok(())
}

/**
 * Sends route entries to the specified destination interface.
 *
 * Inputs:
 * - route_entries: the route entries to send
 * - dest_if: the destination interface
 *
 * Returns:
 * - A Result<()> if successful, Err otherwise
 */
pub fn send_route_entries(route_entries: Vec<RouteEntry>, dst_if: &NetworkInterface) {
    if !route_entries.is_empty() {
        let msg = RIPMessage::new(RIP_RESPONSE, route_entries.len() as u16, route_entries);

        // println!("Sending message: {}", msg);

        // custom match since doesn't return
        if let Ok(()) = send_rip_message(dst_if, msg) {}
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
    dest_if.send_packet_raw(
        payload.as_slice(),
        RIP_PROTOCOL,
        DEFAULT_TTL,
        dest_if.src_addr,
        dest_if.dst_addr,
    )
}

/**
 * Parses a RIP Message from a packet.
 */
fn recv_rip_message(packet: &IPPacket) -> Result<RIPMessage> {
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

/**
 * Handles a RIP Request.
 *
 * Inputs:
 * - rt: the current routing table
 * - net_if: the source of the RIP Request
 * - msg: the RIP request
 * - trigger: the trigger channel
 *
 * Returns:
 * - Nothing on success, an Error on failure
 */
fn handle_rip_request(
    rt: Arc<RoutingTable>,
    net_if: &NetworkInterface,
    msg: &RIPMessage,
    trigger: Sender<Ipv4Addr>,
) -> Result<()> {
    if msg.num_entries > 0 {
        Err(Error::new(
            ErrorKind::Other,
            "RIP requests with more than 1 entry are not currently supported.",
        ))
    } else {
        // remote is dst of network interface, and gateway is src
        let (remote_addr, gateway_addr) = (net_if.dst_addr, net_if.src_addr);

        // let mut routing_table = rt.lock().unwrap();
        // add incoming connection to routing table; has to be best path
        rt.insert(Route {
            dst_addr: remote_addr,
            gateway: gateway_addr,
            next_hop: remote_addr,
            cost: 1,
            mask: INIT_MASK,
            timer: Instant::now(),
        })?;
        // notify trigger of update
        match trigger.send(remote_addr) {
            Ok(()) => (),
            Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
        }

        // process routes into route entries
        let entries = RouteEntry::process_routes(rt.get_routes(), net_if);

        // make new RIP message
        let msg = RIPMessage {
            command: RIP_RESPONSE,
            num_entries: entries.len() as u16,
            entries,
        };

        // send message response!
        send_rip_message(net_if, msg)
    }
}

/**
 * Handles a RIP Response.
 *
 * Inputs:
 * - rt: the current routing table
 * - net_if: the source of the RIP response
 * - msg: the RIP response
 * - trigger: the trigger channel
 *
 * Returns:
 * - Nothing on success, an Error on failure
 */
fn handle_rip_response(
    rt: Arc<RoutingTable>,
    net_if: &NetworkInterface,
    msg: &RIPMessage,
    trigger: Sender<Ipv4Addr>,
) -> Result<()> {
    // remote is dst of network interface, and gateway is src
    let (remote_addr, gateway_addr) = (net_if.dst_addr, net_if.src_addr);

    // let mut routing_table = rt.lock().unwrap();
    // process each entry
    for entry in &msg.entries {
        // first, validate entry
        match entry.validate_entry() {
            Ok(_) => (), //println!("Current entry: {:?}", entry),
            Err(e) => {
                println!("{}", e);
                continue;
            }
        }

        // final destination address of this entry
        let dst_addr = Ipv4Addr::from(entry.address);
        // if valid, update metric
        let new_metric = min(entry.cost + 1, INFINITY);

        if let Some(mut route) = rt.get_route(&dst_addr) {
            // if came from original source, restart timer
            if route.next_hop == remote_addr {
                route.timer = Instant::now();
                rt.insert(route)?;
            }
            // if:
            // - metrics diff and E's src addr == next hop addr
            // - new metric < curr metric
            // - new metric == curr metric and time elapsed >= 6s
            if (new_metric != route.cost && route.next_hop == remote_addr)
                || (new_metric < route.cost)
                || (new_metric == route.cost
                    && route.timer.elapsed() >= Duration::from_secs(ROUTE_TIMEOUT / 2))
            {
                // set metric, and update gateway address and next hop
                route.cost = new_metric;
                route.gateway = gateway_addr;
                route.next_hop = remote_addr;

                // re-initialize the timer; besides timer, don't need additional handling
                // for infinity issues
                if new_metric != INFINITY {
                    route.timer = Instant::now();
                    // println!("Timer reinitialized for route {:?}", route);
                }
                // update routing table
                rt.insert(route)?;

                // signal to trigger that something changed (either delete, or update)
                match trigger.send(dst_addr) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{}", e),
                }
            }
        } else {
            // if not infinity, add to routing table
            if new_metric < INFINITY {
                rt.insert(Route {
                    dst_addr,
                    gateway: gateway_addr,
                    next_hop: remote_addr,
                    cost: new_metric,
                    mask: INIT_MASK,
                    timer: Instant::now(),
                })?;
            }
            // notify trigger that a change has happened on dst_addr
            match trigger.send(dst_addr) {
                Ok(_) => (),
                Err(e) => eprintln!("{}", e),
            }
        };
    }
    Ok(())
}

/**
 * Makes a RIP Handler, given a reference to the RoutingTable and Interfaces.
 *
 * Inputs:
 * - interfaces: the available network interfaces
 * - rt: the routing table
 * - trigger: a trigger channel
 *
 * Returns:
 * - A RIP Handler
 */
pub fn make_rip_handler(
    interfaces: Arc<NetworkInterfaces>,
    rt: Arc<RoutingTable>,
    trigger: Sender<Ipv4Addr>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        // let interfaces = interfaces.read().unwrap();

        // get source (opposite IP) and gateway IP address (this is the destination of the packet!)
        let remote_addr = Ipv4Addr::from(packet.header.source);
        let gateway_addr = Ipv4Addr::from(packet.header.destination);

        // check that source addr is one of the destination interfaces
        let src_if = match interfaces.get_neighbor_if(&remote_addr) {
            Some(net_if) => net_if,
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Source address not from directly connected neighbor!",
                ))
            }
        };

        assert!(gateway_addr == src_if.src_addr);
        assert!(remote_addr == src_if.dst_addr);

        // first, attempt to parse into rip message; validates that protocol is right
        let msg = recv_rip_message(&packet)?;

        // Handle Request
        match msg.command {
            RIP_REQUEST => handle_rip_request(Arc::clone(&rt), src_if, &msg, trigger.clone()),
            RIP_RESPONSE => handle_rip_response(Arc::clone(&rt), src_if, &msg, trigger.clone()),
            _ => Ok(()),
        }
    }))
}
