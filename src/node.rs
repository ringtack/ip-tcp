use crate::protocol::link::READ_TIMEOUT;
use crate::protocol::network::rip::*;
use crate::protocol::network::test::*;
use crate::protocol::network::*;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, Error, ErrorKind, Result},
    mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, RecvTimeoutError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

// pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

pub struct ProtocolHandler {
    pub protocol: u8,
    pub handler: Handler,
}

/**
 * Structure for a Node on the Network.
 *
 * Fields:
 * - interfaces: network interfaces for each of the node's connections. All share the same source
 * socket.
 * - routing_table: dynamically updating table for routes.
 * - handlers: table for registered handlers for different protocols.
 * - receiver: Receiver channel on which Senders send messages.
 */
pub struct Node {
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    handlers: Arc<Mutex<HashMap<u8, Handler>>>,
    thrs: Vec<thread::JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
}

impl Node {
    /**
     * Creates an empty node.
     *
     * Returns:
     * - A Result<Node, Error> with a default node, or error.
     */
    pub fn new_empty() -> Result<Node> {
        Ok(Node {
            interfaces: Arc::new(Mutex::new(Vec::new())),
            routing_table: Arc::new(Mutex::new(RoutingTable::new())),
            handlers: Arc::new(Mutex::new(HashMap::new())),
            thrs: Vec::new(),
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    /**
     * Instantiates a Node from a link file.
     *
     * Inputs:
     * - linksfile: String: the path to a linksfile.
     *
     * Returns:
     * - A Result<Node, Error> with the node configuration specified in the link file, or error.
     */
    pub fn new(linksfile: String, default_handlers: Vec<ProtocolHandler>) -> Result<Node> {
        // Attempt to parse the linksfile
        let lines = read_lines(&linksfile)?;

        // if successful, create initial node
        let mut node = Node::new_empty()?;
        let mut interfaces = node.interfaces.lock().unwrap();
        // store src socket; shared across all interfaces
        let mut src_sock = None;

        // iterate through every line
        for (index, line) in lines.enumerate() {
            let line = line?;
            let line: Vec<&str> = line.split_whitespace().collect();
            // regardless of source or dest, gets addr:port
            let sock_addr =
                SocketAddrV4::new(str_2_ipv4(line[0])?, line[1].parse::<u16>().unwrap());

            // if first line, is source "L2 address"
            if index == 0 {
                // Create socket on which node will listen
                println!("[Node::new] Listening on {}...", sock_addr);

                let sock = UdpSocket::bind(sock_addr)?;
                sock.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT)))?;
                src_sock = Some(sock);
                continue;
            }

            // otherwise, make network interface:
            //      <Dest L2 Address> <Dest L2 Port> <Src IF> <Dest IF>
            let src_addr = str_2_ipv4(line[2])?;
            let dest_addr = str_2_ipv4(line[3])?;

            if let Some(sock) = &src_sock {
                interfaces.push(NetworkInterface::new(
                    (index - 1) as u8,
                    src_addr,
                    dest_addr,
                    sock,
                    sock_addr,
                )?);
            }

            // insert into routing table
            insert_route(
                Arc::clone(&node.routing_table),
                Route {
                    dst_addr: src_addr,
                    gateway: src_addr,
                    next_hop: src_addr,
                    cost: 0,
                    changed: false,
                    mask: INIT_MASK,
                    timer: Instant::now(),
                },
            )?;
        }

        // Set up timeout/cleanup thread (rx will be used later for trigger response thread)
        let (tx, rx) = channel::<Ipv4Addr>();
        let rt = Arc::clone(&node.routing_table);
        let tx1 = tx.clone();
        let stopped = Arc::clone(&node.stopped);
        node.thrs.push(thread::spawn(move || loop {
            // if stopped, we're finished
            if stopped.load(Ordering::Relaxed) {
                return;
            }

            // every CHECK_TIMEOUTS (500) milliseconds, scan list for timeouts/cleanups
            thread::sleep(Duration::from_millis(CHECK_TIMEOUTS));

            let timeout = Duration::from_secs(TIMEOUT);
            let mut rt = rt.lock().unwrap();
            // for each route:
            for (dst_addr, route) in rt.iter_mut() {
                // if (not a local entry (i.e. cost > 0) and time since now and last updated >
                // TIMEOUT) OR (if cost is INFINITY), notify trigger of timeout
                if (route.cost > 0 && route.timer.elapsed() > timeout) || route.cost == INFINITY {
                    // println!(
                    // "Route to {} expired ({:?})... cleaning up",
                    // route.dst_addr,
                    // route.timer.elapsed()
                    // );

                    // before notifying, need to mark route as changed and set metric to INFINITY
                    route.changed = true;
                    route.cost = INFINITY;
                    tx1.send(*dst_addr).unwrap();
                }
            }
        }));

        // Set up trigger response thread
        let rt = Arc::clone(&node.routing_table);
        let ifs = Arc::clone(&node.interfaces);
        let stopped = Arc::clone(&node.stopped);
        node.thrs.push(thread::spawn(move || {
            let mut rng = rand::thread_rng();
            loop {
                // if stopped, we're finished
                if stopped.load(Ordering::Relaxed) {
                    return;
                }

                // Accumulate messages for somewhere between 200-500ms; RFC recommends
                // 1-5s
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
                            let rt = rt.lock().unwrap();
                            if rt.has_dst(&dst_addr) {
                                updated_routes.push(rt.get_route(&dst_addr).unwrap());
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

                let ifs = ifs.lock().unwrap();
                // for each network interface, process then send
                for dst_if in &*ifs {
                    match RoutingTable::process_updates(&updated_routes, &mut to_delete, dst_if) {
                        // if properly converted and not empty, send RIP message
                        Ok(route_entries) => {
                            if !route_entries.is_empty() {
                                // println!("sending to {}", dst_if.dst_addr);
                                send_route_entries(dst_if, route_entries)
                            }
                        }
                        // otherwise, display error
                        Err(e) => eprintln!("{}", e),
                    }
                }
                // don't need lock on IFs anymore
                mem::drop(ifs);

                // finally, for all expired routes, delete!
                let mut rt = rt.lock().unwrap();
                for expired_dst in to_delete {
                    rt.delete(&expired_dst);
                }
            }
        }));

        // Configure handlers
        let mut handlers = node.handlers.lock().unwrap();
        // add any default handlers provided
        for ph in default_handlers {
            handlers.insert(ph.protocol, Arc::clone(&ph.handler));
        }
        // register test handler
        handlers.insert(
            TEST_PROTOCOL,
            make_test_handler(
                Arc::clone(&node.interfaces),
                Arc::clone(&node.routing_table),
            ),
        );
        // register rip handler
        handlers.insert(
            RIP_PROTOCOL,
            make_rip_handler(
                Arc::clone(&node.interfaces),
                Arc::clone(&node.routing_table),
                tx,
            ),
        );
        // done, so drop ref
        mem::drop(handlers);

        // Send RIP Request to each of its net interfaces (i.e. neighbors)
        for dest_if in &*interfaces {
            let rip_msg = RIPMessage::new(RIP_REQUEST, 0, vec![]);
            send_rip_message(dest_if, rip_msg)?;
        }

        // Configure periodic RIP updates
        let rt = Arc::clone(&node.routing_table);
        let ifs = Arc::clone(&node.interfaces);
        let stopped = Arc::clone(&node.stopped);
        // move references into thread
        node.thrs.push(thread::spawn(move || loop {
            // if stopped, we're finished
            // sleep for 1s at a time, checking if we should terminate
            for _ in 0..5 {
                if stopped.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_secs(UPDATE_TIME / 5));
            }

            let routing_table = rt.lock().unwrap();
            let interfaces = ifs.lock().unwrap();
            // for each network interface:
            for dst_if in &*interfaces {
                // get processed route entries; need match since this doesn't return
                match routing_table.get_entries(dst_if) {
                    Ok(route_entries) => send_route_entries(dst_if, route_entries),
                    Err(e) => eprintln!("{}", e),
                };
            }
        }));

        // Initiate thread to listen for incoming packets; rx will be used to receive packets
        let (tx, rx) = channel::<IPPacket>();
        for net_if in &*interfaces {
            let ifs = Arc::clone(&node.interfaces);
            let tx = tx.clone();
            let net_if = net_if.clone();
            let stopped = Arc::clone(&node.stopped);
            node.thrs.push(thread::spawn(move || {
                // infinitely listen for incoming messages
                loop {
                    // if stopped, we're finished
                    if stopped.load(Ordering::Relaxed) {
                        return;
                    }
                    match net_if.recv_ip() {
                        Ok((packet, src_addr)) => {
                            // only forward if the actual link interface was active
                            // TODO: this should really be a part of the link interface... Alas,
                            // since only one socket for every link interface, we're stuck with a
                            // check here. I HATE THE UDP SOCKET ABSTRACTION AHHH
                            let ifs = ifs.lock().unwrap();
                            if gateway_active(&src_addr, &*ifs) {
                                // TODO: error checking
                                tx.send(packet).unwrap()
                            }
                        }
                        Err(e) => match e.kind() {
                            // if not connected, link is down, so sleep for a bit
                            ErrorKind::NotConnected => {
                                thread::sleep(Duration::from_millis(500));
                                // eprintln!("link not up");
                            }
                            // if didn't receive anything, wait for a bit
                            ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                                thread::sleep(Duration::from_millis(200));
                            }
                            // otherwise, probably something wrong with packet, so emit error
                            _ => eprintln!("{}", e),
                        },
                    }
                }
            }));
        }

        // Finally, infinitely process incoming messages
        let handlers = Arc::clone(&node.handlers);
        let stopped = Arc::clone(&node.stopped);
        node.thrs.push(thread::spawn(move || {
            for packet in rx {
                // if stopped, we're finished
                if stopped.load(Ordering::Relaxed) {
                    return;
                }

                let protocol = packet.header.protocol;
                let handlers = handlers.lock().unwrap();
                if handlers.contains_key(&protocol) {
                    let mut handler = handlers[&protocol].lock().unwrap();
                    match handler(packet) {
                        Ok(()) => (),
                        Err(e) => eprintln!("{}", e),
                    }
                }
            }
        }));
        // unlock before returning to prevent borrow checker from complaining
        mem::drop(interfaces);

        // print interfaces
        println!("{}", node.fmt_startup_interfaces());

        Ok(node)
    }

    pub fn quit(&mut self) {
        // notify all threads that we're done by updating stopped flag
        self.stopped.store(true, Ordering::Relaxed);

        // join all threads
        while let Some(cur_thr) = self.thrs.pop() {
            cur_thr.join().expect("Thread failed to join.");
        }

        // for each local interface, make RouteEntrys to each
        let interfaces = self.interfaces.lock().unwrap();

        let mut dead_routes = Vec::with_capacity(interfaces.len());
        for local_if in &*interfaces {
            // make route entry
            dead_routes.push(RouteEntry {
                cost: INFINITY,
                address: local_if.src_addr.into(),
                mask: INIT_MASK,
            });
        }

        let msg = RIPMessage::new(RIP_RESPONSE, dead_routes.len() as u16, dead_routes);
        // send dead routes to all interfaces
        for net_if in &*interfaces {
            match send_rip_message(net_if, msg.clone()) {
                Ok(()) => (),
                Err(e) => match e.kind() {
                    ErrorKind::NotConnected => eprintln!("{}", e),
                    _ => {
                        eprintln!("Should be able to send exit RIP message! Got error: {}", e);
                        process::exit(1);
                    }
                },
            }
        }
        // ... aaaand we're done! :D
    }

    // Getters that we don't need (for now).

    /*
     * Register handler for a specific protocol.
     *
     * Inputs:
     * - protocol: the protocol for which a handler should be registered
     * - handler: the handler for the specific protocol.
     */
    // pub fn register_handler(&self, protocol: u8, handler: Handler) {
    // let mut handlers = self.handlers.lock().unwrap();
    // handlers.insert(protocol, handler);
    // }

    // pub fn get_interfaces(&self) -> Arc<Mutex<Vec<NetworkInterface>>> {
    // Arc::clone(&self.interfaces)
    // }

    // pub fn get_routing_table(&self) -> Arc<Mutex<RoutingTable>> {
    // Arc::clone(&self.routing_table)
    // }

    // pub fn get_handlers(&self) -> Arc<Mutex<HashMap<u8, Handler>>> {
    // Arc::clone(&self.handlers)
    // }

    pub fn invoke_handler(&self, protocol: u8, packet: IPPacket) -> Result<()> {
        let handlers = self.handlers.lock().unwrap();
        if handlers.contains_key(&protocol) {
            let mut handler = handlers[&protocol].lock().unwrap();
            handler(packet)?;
        }

        Ok(())
    }

    /**
     * Converts network interfaces into a string to display on startup.
     */
    pub fn fmt_startup_interfaces(&self) -> String {
        let mut res = String::new();
        let interfaces = self.interfaces.lock().unwrap();
        for (index, interface) in interfaces.iter().enumerate() {
            res.push_str(&(format!("{}:\t{}", interface.id, interface.src_addr)));
            if index != interfaces.len() - 1 {
                res.push('\n');
            }
        }
        res
    }

    /**
     * Converts network interfaces into a human-readable string.
     */
    pub fn fmt_interfaces(&self) -> String {
        let mut res = String::new();
        let interfaces = self.interfaces.lock().unwrap();
        res.push_str("id\trem\t\tloc\n");
        for (index, interface) in interfaces.iter().enumerate() {
            if !interface.link_if.active.load(Ordering::Relaxed) {
                continue;
            }
            res.push_str(
                &(format!(
                    "{}\t{}\t{}",
                    interface.id, interface.dst_addr, interface.src_addr
                )),
            );
            if index != interfaces.len() - 1 {
                res.push('\n');
            }
        }
        res
    }

    /**
     * Converts routing table into a human-readable string.
     */
    pub fn fmt_routes(&self) -> String {
        let mut res = String::new();
        res.push_str("cost\tdst\t\tloc\n");
        // let interfaces = self.interfaces.lock().unwrap();
        let routing_table = self.routing_table.lock().unwrap();

        for (index, (_, route)) in routing_table.iter().enumerate() {
            // only display if cost is not INFINITY
            if route.cost != INFINITY {
                res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.gateway)));
                if index != routing_table.size() - 1 {
                    res.push('\n');
                }
            }
        }
        res
    }

    /**
     * Bring the link of an interface "down"
     */
    pub fn interface_link_down(&mut self, id: isize) -> Result<()> {
        let mut interfaces = self.interfaces.lock().unwrap();

        // check if is valid interface
        if id < 0 || id as usize >= interfaces.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "interface {} out of bounds : (0 to {})",
                    id,
                    interfaces.len()
                ),
            ));
        }

        // get mutable reference to interface we're bringing down
        let down_if = &mut interfaces[id as usize];
        if !down_if.link_if.active.load(Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is down already", id),
            ));
        }
        down_if.link_if.link_down();

        // after bringing down, set all route costs with this gateway interface to INFINITY;
        // cleanup thread will pick up and delete
        let mut routing_table = self.routing_table.lock().unwrap();
        for (_, route) in routing_table.iter_mut() {
            // if gateway shares same source interface as this interface, "bring down"
            if route.gateway == down_if.src_addr {
                route.cost = INFINITY;
                route.changed = true;
            }
        }
        // Note that this doesn't actually inform direct neighbors about the change until 12s
        // later; can try to remedy by sleeping for 1s, but not really optimal

        Ok(())
    }

    /**
     * Bring the link of an interface "up"
     */
    pub fn interface_link_up(&mut self, id: isize) -> Result<()> {
        let mut interfaces = self.interfaces.lock().unwrap();

        // check if valid interface
        if id < 0 || id as usize >= interfaces.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "interface {} out of bounds : (0 to {})",
                    id,
                    interfaces.len()
                ),
            ));
        }

        // check if already up
        let up_if = &mut interfaces[id as usize];
        if up_if.link_if.active.load(Ordering::Relaxed) {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is up already", id),
            ));
        }
        up_if.link_if.link_up();

        // add to routing table this local route; will send out in next periodic update
        // TODO: send out as triggered update: do this by adding the trigger channel as a field to
        // node
        // TODO: so apparently this does get sent out almost instantly... howe LOL
        let mut routing_table = self.routing_table.lock().unwrap();
        routing_table.insert(Route {
            dst_addr: up_if.src_addr,
            gateway: up_if.src_addr,
            next_hop: up_if.src_addr,
            cost: 0,
            changed: false,
            mask: INIT_MASK,
            timer: Instant::now(),
        })?;
        Ok(())
    }

    /**
     * Send data with specified protocol
     */
    pub fn send_data(&mut self, ip: String, protocol: u8, payload: String) -> Result<()> {
        let dst_addr = str_2_ipv4(&ip)?;

        // find local network interface associated with destination
        let interfaces = self.interfaces.lock().unwrap();
        // if on local net, pass off to handlers
        if let Some(index) = if_local(&dst_addr, &*interfaces) {
            // make IP packet
            let local_if = &interfaces[index];
            let packet = IPPacket::new(
                local_if.src_addr,
                dst_addr,
                payload.as_bytes().into(),
                DEFAULT_TTL,
                protocol,
            );
            // don't need lock anymore
            mem::drop(interfaces);

            // invoke handler
            return self.invoke_handler(protocol, packet);
        }

        let routing_table = self.routing_table.lock().unwrap();
        // check if one of the destinations
        if !routing_table.has_dst(&dst_addr) {
            return Err(Error::new(ErrorKind::Other, "Destination not reachable!"));
        }

        let gateway_addr = routing_table.get_route(&dst_addr)?.gateway;
        // ensure that gateway is actually a local interface
        if let Some(gateway_if_index) = if_local(&gateway_addr, &*interfaces) {
            let nexthop_if = &interfaces[gateway_if_index];

            // println!(
            // "Sending data from {} to {}...",
            // nexthop_if.src_addr, dst_addr
            // );

            // make IP packet and send
            nexthop_if.send_ip(payload.as_bytes(), protocol, nexthop_if.src_addr, dst_addr)
        } else {
            Err(Error::new(ErrorKind::Other, "Destination not reachable!"))
        }
    }
}

/**
 * Helper function to send route entries to a destination interface.
 */
fn send_route_entries(dst_if: &NetworkInterface, route_entries: Vec<RouteEntry>) {
    if !route_entries.is_empty() {
        let msg = RIPMessage::new(RIP_RESPONSE, route_entries.len() as u16, route_entries);

        // println!("Sending message: {}", msg);

        // custom match since doesn't return
        if let Ok(()) = send_rip_message(dst_if, msg) {}
    }
}

/**
 * Helper function to read all lines of a file specified by the path filename.
 */
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

/**
 * Converts a string into an IP address.
 */
fn str_2_ipv4(s: &str) -> Result<Ipv4Addr> {
    if s == "localhost" {
        Ok(Ipv4Addr::LOCALHOST)
    } else {
        match s.parse::<Ipv4Addr>() {
            Ok(ip) => Ok(ip),
            Err(_) => Err(Error::new(ErrorKind::Other, "invalid IP address")),
        }
    }
}
