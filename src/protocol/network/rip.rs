use std::collections::HashMap;
use std::net::Ipv4Addr;

const MAX_ROUTES: usize = 128;
const MAX_TTL: usize = 128;
const INFINITY: usize = 16;

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
