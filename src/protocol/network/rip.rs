use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MAX_ROUTES: usize = 64;
pub const DEFAULT_TTL: u8 = 16; // TODO: which value???
pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

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
 * Struct representing a route entry in a RIP message.
 *
 * Fields:
 * - cost: cost to reach destination
 * - address: destination address
 * - mask: netmask; default is 255.255.255.255
 */
#[repr(packed)]
pub struct RouteEntry {
    pub cost: u32,
    pub address: u32,
    pub mask: u32,
}

/**
 * Dummy route for initial RIP request.
 */
pub const DUMMY_ROUTE: RouteEntry = RouteEntry {
    cost: INFINITY,
    address: 0,
    mask: INIT_MASK,
};

/**
 * RIP Message.
 *
 * Fields:
 * - command: either 1 (request) or 2 (response)
 * - num_entries: number of RouteEntries
 * - entries: vector of entries
 */
#[repr(packed)]
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
}
