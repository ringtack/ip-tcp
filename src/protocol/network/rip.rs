use std::collections::HashSet;
use std::net; // maybe HashMap?

const MAX_ROUTES: usize = 128;
const MAX_TTL: usize = 128;

#[derive(Hash, Eq)]
pub struct Route {
    pub dst_addr: net::Ipv4Addr,
    pub next_hop: net::Ipv4Addr,
    pub cost: usize,
    pub ttl: usize,
}

pub struct RoutingTable {
    routes: HashSet<Route>,
    // add synchronization primitives
}

impl RoutingTable {
    pub fn new(routes: Vec<Route>) -> RoutingTable {
        RoutingTable {
            routes: HashSet::from_iter(routes.iter()), // TODO: do we need to clone
        }
    }
}

#[repr(packed)]
pub struct Entry {
    pub cost: u32,
    pub address: u32,
    pub mask: u32,
}

#[repr(packed)]
pub struct RIPMessage {
    command: u16,
    num_entries: u16,
    entries: Vec<Entry>,
}

impl RIPMessage {
    pub fn new(command: u16, num_entries: u16, entries: Vec<Entry>) -> RIPMessage {
        RIPMessage {
            command,
            num_entries,
            entries,
        }
    }
}
