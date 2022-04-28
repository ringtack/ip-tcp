// pub mod icmp;
pub mod ip_packet;
pub mod network_interfaces;
pub mod rip;
pub mod routing_table;
pub mod test;

use crate::protocol::link::MTU;

use dashmap::DashMap;

use rand::Rng;
use std::{
    collections::HashSet,
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

// use self::icmp::*;
use self::ip_packet::*;
use self::network_interfaces::*;
use self::rip::*;
use self::routing_table::*;

pub const INFINITY: u32 = 16;
pub const INIT_MASK: u32 = u32::MAX;

pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

/**
 * Struct representing the network layer interface.
 */
#[derive(Clone)]
pub struct InternetModule {
    pub routing_table: Arc<RoutingTable>,
    pub interfaces: Arc<NetworkInterfaces>,
    pub handlers: Arc<DashMap<u8, Handler>>,
}

impl InternetModule {
    pub fn new(
        routing_table: Arc<RoutingTable>,
        interfaces: Arc<NetworkInterfaces>,
        handlers: Arc<DashMap<u8, Handler>>,
    ) -> InternetModule {
        InternetModule {
            routing_table,
            interfaces,
            handlers,
        }
    }

    pub fn register_handler(&self, protocol: u8, handler: Handler) {
        self.handlers.insert(protocol, handler);
    }

    /**
     * Gets the gateway address of the route to the destination address.
     *
     * Returns:
     * - the gateway address of the network interface, or None if no route.
     */
    pub fn get_gateway(&self, addr: &Ipv4Addr) -> Option<Ipv4Addr> {
        self.routing_table
            .get_route(addr)
            .map(|route| route.gateway)
    }

    /**
     * Forwards the packet to its final destination (should not be a local IP address!).
     *
     * Inputs:
     * - packet: the IP Packet to send
     *
     * Returns:
     * - Ok(()) if successfully sent, Error otherwise
     */
    pub fn send_ip(&self, packet: IPPacket) -> Result<()> {
        let dst_addr = Ipv4Addr::from(packet.header.destination);
        // check if routing table has destination; throw error if not
        if let Some(route) = self.routing_table.get_route(&dst_addr) {
            // attempt to send through gateway interface
            if let Some(net_if) = self.interfaces.get_local_if(&route.gateway) {
                return net_if.send_packet(packet);
            }
        }

        // if route doesn't exist, or can't send to local gateway, throw error
        Err(Error::new(
            ErrorKind::Other,
            "[Route] Destination not reachable!",
        ))
    }

    /**
     * Handles a received packet: if local, pass to handlers; if remote, forward.
     *
     * Inputs:
     * - packet: the packet to handle
     */
    pub fn handle_ip(&self, mut packet: IPPacket) {
        // TODO: fragment re-assembly
        if packet.size() > MTU {
            eprintln!("Packet too large (size: {}, MTU: {})", packet.size(), MTU);
            return;
        }

        let dst_addr = Ipv4Addr::from(packet.header.destination);

        let is_local = self.interfaces.is_local_if(&dst_addr);
        // if receiving interface was local, pass to handler
        if is_local {
            let protocol = packet.header.protocol;
            if self.handlers.contains_key(&protocol) {
                let handler = match self.handlers.get_mut(&protocol) {
                    Some(handler) => handler,
                    None => {
                        eprintln!("Received invalid protocol {}", protocol);
                        return;
                    }
                };
                // let mut handler = self.handlers[&protocol].lock().unwrap();
                let mut handler = handler.lock().unwrap();
                if handler(packet).is_ok() {}
            }
        } else {
            // println!("{:#?}", packet.header);

            // otherwise, decrement packet TTL and compute checksum
            packet.header.time_to_live -= 1;
            packet.header.header_checksum = match packet.header.calc_header_checksum() {
                Ok(checksum) => checksum,
                Err(e) => {
                    eprintln!("{}", e);
                    return;
                }
            };

            // TODO: if time to live reaches 0, send ICMP Time Exceeded response back to source
            if packet.header.time_to_live == 0 {
                // ICMPMessage::new(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, type: u8, code: u8,
                // packet: IPPacket)
            } else {
                // otherwise, forward to destination
                if self.send_ip(packet).is_ok() {}
            }
        }
    }

    /**
     * Send exit messages to network interfaces.
     */
    pub fn send_exit_msg(&self) {
        // for each local interface, make RouteEntrys to each

        // collect dead routes
        let dead_routes: Vec<RouteEntry> = self
            .interfaces
            .iter()
            .map(|net_if| RouteEntry {
                cost: INFINITY,
                address: u32::from_be_bytes(net_if.src_addr.octets()),
                mask: INIT_MASK,
            })
            .collect();

        let msg = RIPMessage::new(RIP_RESPONSE, dead_routes.len() as u16, dead_routes);
        // send dead routes to all interfaces
        for net_if in self.interfaces.iter() {
            if send_rip_message(net_if, msg.clone()).is_ok() {}
        }
    }

    /**
     * Bring the link of an interface "down"
     */
    pub fn interface_link_down(&mut self, id: isize) -> Result<()> {
        // find interface we're bringing down
        let mut down_if = self.interfaces.find_interface_id(id)?;

        // throw error if already down
        if !down_if.is_active() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is down already", id),
            ));
        }
        down_if.link_if.link_down();

        // after bringing down, set all route costs with this gateway interface to INFINITY;
        // cleanup thread will pick up and delete (after at most 500ms)
        for mut rt_entry in self.routing_table.iter_mut() {
            let route = rt_entry.value_mut();
            // if gateway shares same source interface as this interface, "bring down"
            if route.gateway == down_if.src_addr {
                route.cost = INFINITY;
            }
        }

        Ok(())
    }

    /**
     * Bring the link of an interface "up"
     */
    pub fn interface_link_up(&mut self, id: isize, trigger: Sender<Ipv4Addr>) -> Result<()> {
        // find interface we're bringing up
        let mut up_if = self.interfaces.find_interface_id(id)?;

        // throw error if already up
        if up_if.is_active() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is up already", id),
            ));
        }
        up_if.link_if.link_up();

        // add to routing table this local route; will send out in next periodic update
        self.routing_table.insert(Route {
            dst_addr: up_if.src_addr,
            gateway: up_if.src_addr,
            next_hop: up_if.src_addr,
            cost: 0,
            mask: INIT_MASK,
            timer: Instant::now(),
        })?;

        // send as triggered update
        trigger.send(up_if.src_addr).unwrap();
        Ok(())
    }

    /**
     * Get formatted startup interface string.
     */
    pub fn fmt_startup_interfaces(&self) -> String {
        self.interfaces.fmt_startup_interfaces()
    }

    /**
     * Get formatted interface string.
     */
    pub fn fmt_interfaces(&self) -> String {
        self.interfaces.fmt_interfaces()
    }

    /**
     * Get formatted route string.
     */
    pub fn fmt_routes(&self) -> String {
        self.routing_table.fmt_routes()
    }

    /*
     * THREAD HANDLER SETUP
     */
    /**
     * Make trigger response thread.
     *
     * Inputs:
     * - rx: receiver for triggered updates
     * - stopped: flag to indicate whether stopped
     */
    pub fn make_trigger_response(
        &self,
        rx: Receiver<Ipv4Addr>,
        stopped: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        let (rt, ifs) = (self.routing_table.clone(), self.interfaces.clone());
        thread::spawn(move || loop {
            let mut rng = rand::thread_rng();

            // if stopped, we're finished
            if stopped.load(Ordering::Relaxed) {
                return;
            }

            // Accumulate messages for sometime between 200-500ms; RFC recommends 1-5s
            let start_time = Instant::now();
            let get_duration = Duration::from_millis(rng.gen_range(200..500));
            let mut updated_routes = Vec::new();

            // keep matching until timeout
            loop {
                let now = Instant::now();
                // if too much time elapsed, quit out
                if start_time + get_duration <= now {
                    break;
                }
                // time left to wait
                let duration = start_time + get_duration - now;
                // block until duration ends, or a message is sent
                match rx.recv_timeout(duration) {
                    Ok(dst_addr) => {
                        if let Some(route) = rt.get_route(&dst_addr) {
                            updated_routes.push(route);
                        }
                    }
                    // in this case, timer up
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        // handle shutdown
                        eprintln!("Trigger connection closed. Shutting down...");
                        return;
                    }
                }
            }

            // if no updates, just continue
            if updated_routes.is_empty() {
                continue;
            }

            // now, send updates to all nodes, with processing:
            // - if a route's metric is INFINITY, mark for deletion
            // - SH w/ PR
            let mut to_delete = HashSet::new();
            for dest_if in ifs.iter() {
                let route_entries =
                    RouteEntry::process_updates(&updated_routes, &mut to_delete, dest_if);
                send_route_entries(route_entries, dest_if)
            }

            // finally, for all expired routes, delete!
            to_delete
                .into_iter()
                .for_each(|expired_dst| rt.delete(&expired_dst));
        })
    }

    /**
     * Make periodic updates thread.
     *
     * Inputs:
     * - stopped: flag to indicate whether stopped
     */
    pub fn make_periodic_updates(&self, stopped: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        let (rt, ifs) = (self.routing_table.clone(), self.interfaces.clone());
        thread::spawn(move || loop {
            // if stopped, we're finished
            // sleep for 1s at a time, checking if we should terminate
            for _ in 0..5 {
                if stopped.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_secs(UPDATE_TIME / 5));
            }

            // for each network interface:
            for dest_if in ifs.iter() {
                // get processed route entries, and send
                if send_routes(rt.get_routes(), dest_if).is_ok() {}
            }
        })
    }

    /**
     * Make IP Listener thread to handle incoming packets.
     */
    pub fn make_ip_listener(&self, stopped: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        let this = self.clone();
        // get any NetworkInterface from the list of interfaces
        let net_if = this.interfaces.get_net_if();
        thread::spawn(move || loop {
            // if stopped, we're done
            if stopped.load(Ordering::Relaxed) {
                return;
            }
            //  doesn't matter which one accepts, since UDP abstraction prevents differentiation...
            match net_if.recv_packet() {
                Ok((packet, src_addr)) => {
                    // only send if source link is up
                    if this.interfaces.link_active(&src_addr) {
                        this.handle_ip(packet)
                    }
                }
                Err(e) => match e.kind() {
                    // if not connected, link is down, so sleep for a bit
                    ErrorKind::NotConnected => {
                        thread::sleep(Duration::from_millis(200));
                        // eprintln!("link not up");
                    }
                    // if didn't receive anything, re-run
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                        // thread::sleep(Duration::from_millis(200));
                    }
                    // otherwise, probably something wrong with packet, so emit error
                    _ => eprintln!("{}", e),
                },
            }
        })
    }
}
