use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MAX_ROUTES: usize = 64;
pub const DEFAULT_TTL: u8 = 16; // TODO: which value???
pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

#[derive(Hash, PartialEq, Eq)]
pub struct Route {
    pub dst_addr: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub cost: usize,
    pub changed: bool,
}

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
}

#[repr(packed)]
pub struct RouteEntry {
    pub cost: u32,
    pub address: u32,
    pub mask: u32,
}

pub const DUMMY_ROUTE: RouteEntry = RouteEntry {
    cost: INFINITY,
    address: 0,
    mask: INIT_MASK,
};

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
