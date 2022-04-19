use dashmap::{
    iter::{Iter, IterMut},
    DashMap,
};

use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::protocol::network::INFINITY;

pub const MAX_ROUTES: usize = 64;
pub const CHECK_TIMEOUTS: u64 = 500;
pub const ROUTE_TIMEOUT: u64 = 12;

/**
 * Routing Table. Maps destination addresses to routes.
 */
pub struct RoutingTable {
    routes: DashMap<Ipv4Addr, Route>,
}

impl RoutingTable {
    pub fn new() -> RoutingTable {
        RoutingTable {
            routes: DashMap::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.routes.len()
    }

    /**
     * Fetches a route to the destination address, if one exists.
     *
     * Inputs:
     * - dst_addr: the desired destination
     *
     * Returns:
     * - Some(Route) if exists, None otheriwse
     */
    pub fn get_route(&self, dst_addr: &Ipv4Addr) -> Option<Route> {
        self.routes.get(dst_addr).map(|route| *route)
    }

    /**
     * Gets the routes as a vector.
     *
     * Returns:
     * - A Vec<Route> consisting of all current routes.
     */
    pub fn get_routes(&self) -> Vec<Route> {
        self.routes.iter().map(|e| *e.value()).collect()
    }

    /**
     * Attempts to insert a route into the RoutingTable. If full, returns an error.
     *
     * Inputs:
     * - route: the Route to insert
     *
     * Returns:
     * - Ok() if success, Err() otherwise
     */
    pub fn insert(&self, route: Route) -> Result<()> {
        match self.routes.contains_key(&route.dst_addr) || self.size() < MAX_ROUTES {
            true => {
                self.routes.insert(route.dst_addr, route);
                Ok(())
            }
            false => Err(Error::new(ErrorKind::Other, "Too many routes.")),
        }
    }

    /**
     * Deletes route from the routing table.
     */
    pub fn delete(&self, dst_addr: &Ipv4Addr) {
        self.routes.remove(dst_addr);
    }

    pub fn iter(&self) -> Iter<'_, Ipv4Addr, Route> {
        self.routes.iter()
    }

    pub fn iter_mut(&self) -> IterMut<'_, Ipv4Addr, Route> {
        self.routes.iter_mut()
    }

    /**
     * converts routing table into a human-readable string.
     */
    pub fn fmt_routes(&self) -> String {
        let mut res = String::new();
        res.push_str("cost\tdst\t\tloc\n");

        for (index, route) in self.iter().enumerate() {
            // only display if cost is not infinity
            if route.cost != INFINITY {
                res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.gateway)));
                if index != self.size() - 1 {
                    res.push('\n');
                }
            }
        }
        res
    }

    /**
     * Start cleanup thread for a routing table.
     *
     * Inputs:
     * - rt: the routing table to periodically cleanup
     * - trigger: sender to which to send updates
     * - stopped: check if stopped
     *
     * Returns:
     * - thread::JoinHandle<()> for cleanup later
     */
    pub fn make_rt_cleanup(
        rt: Arc<RoutingTable>,
        trigger: Sender<Ipv4Addr>,
        stopped: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            // if stopped, we're finished
            if stopped.load(Ordering::Relaxed) {
                return;
            }
            // every CHECK_TIMEOUTS (500) milliseconds, scan list for timeouts/cleanups
            thread::sleep(Duration::from_millis(CHECK_TIMEOUTS));

            let timeout = Duration::from_secs(ROUTE_TIMEOUT);
            // let mut rt = rt.lock().unwrap();
            // for each route:
            for mut route_entry in rt.iter_mut() {
                let dst_addr = *route_entry.key();
                let route = route_entry.value_mut();
                // let mut route = route_entry.value().clone();
                // if:
                // - not a local entry (i.e. cost > 0) and time since now and last updated > TIMEOUT
                // - cost is INFINITY
                // notify trigger of timeout
                if (route.cost > 0 && route.timer.elapsed() > timeout) || route.cost == INFINITY {
                    // println!(
                    // "Route to {} timed out [{:?}]",
                    // route.dst_addr,
                    // route.timer.elapsed()
                    // );

                    // before notifying, need to set metric to INFINITY
                    route.cost = INFINITY;
                    match trigger.send(dst_addr) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{}", e),
                    }
                }
            }
        })
    }
}

/**
 * Struct representing a Route in the RoutingTable.
 *
 * Fields:
 * - dst_addr: the destination address
 * - next_hop: the remote IP address to the next node in the route
 * - gateway: local (gateway) IP address to the next node in the route
 * - cost: the cost to reach the destination
 */
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct Route {
    pub dst_addr: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub cost: u32,
    pub mask: u32,
    pub timer: Instant,
}
