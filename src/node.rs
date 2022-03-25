use crate::protocol::network::rip::*;
use crate::protocol::network::test::*;
use crate::protocol::network::{IPPacket, NetworkInterface, RIP_PROTOCOL, TEST_PROTOCOL};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, Error, ErrorKind, Result},
    mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::{
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
    // interfaces: Vec<NetworkInterface>,
    // routing_table: RoutingTable,
    // handlers: HashMap<u8, Handler>,
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    handlers: Arc<Mutex<HashMap<u8, Handler>>>,
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
        let node = Node::new_empty()?;
        let mut interfaces = node.interfaces.lock().unwrap();
        // store src socket; shared across all interfaces
        let mut src_sock: Option<UdpSocket> = None;

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

                src_sock = Some(UdpSocket::bind(sock_addr)?);
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

        // Set up timeout thread (rx will be used later for trigger response thread)
        let (tx, rx) = channel::<Ipv4Addr>();
        let rt = Arc::clone(&node.routing_table);
        let tx1 = tx.clone();
        thread::spawn(move || loop {
            // every CHECK_TIMEOUTS seconds, scan list for timeouts
            thread::sleep(Duration::from_secs(CHECK_TIMEOUTS));

            let mut rt = rt.lock().unwrap();
            // for each route:
            for (dst_addr, route) in rt.iter_mut() {
                // if not a local entry (i.e. cost > 0) and time since now and last updated >
                // TIMEOUT, notify trigger of timeout
                if route.cost > 0 && route.timer.elapsed() > Duration::from_secs(TIMEOUT) {
                    // before notifying, need to mark route as changed and set metric to INFINITY
                    route.changed = true;
                    route.cost = INFINITY;
                    tx1.send(*dst_addr).unwrap();
                }
            }
        });

        // Set up trigger response thread
        let rt = Arc::clone(&node.routing_table);
        let ifs = Arc::clone(&node.interfaces);
        thread::spawn(move || {
            let mut rng = rand::thread_rng();
            loop {
                // TODO: should I do this?
                // Accumulate messages for somewhere between 200-1000ms; RFC recommends
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
                        // if properly converted, send RIP message
                        Ok(route_entries) => send_route_entries(dst_if, route_entries),
                        // otherwise, dislpay error
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
        });

        // Configure handlers
        let mut handlers = node.handlers.lock().unwrap();
        // add any default handlers provided
        for ph in default_handlers {
            handlers.insert(ph.protocol, Arc::clone(&ph.handler));
        }
        // TODO: register test handler
        handlers.insert(
            TEST_PROTOCOL,
            make_test_handler(
                Arc::clone(&node.interfaces),
                Arc::clone(&node.routing_table),
            ),
        );
        // handlers.insert(...);
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
        // move references into thread
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(UPDATE_TIME)); // update every 5 seconds

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
        });

        // Initiate thread to listen for incoming packets
        // TODO: only one listener, or multiple?
        let (tx, rx) = channel::<IPPacket>();

        for net_if in &*interfaces {
            let tx = tx.clone();
            let net_if = net_if.clone();
            // TODO: store result so we can cancel somewhere
            thread::spawn(move || {
                // infinitely listen for incoming messages
                loop {
                    // TODO: error handling
                    let packet = net_if.recv_ip().unwrap();
                    tx.send(packet).unwrap();
                }
            });
        }

        // Finally, infinitely process incoming messages
        // TODO: store result somewhere
        let handlers = Arc::clone(&node.handlers);
        thread::spawn(move || {
            for packet in rx {
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
        });

        // unlock before returning to prevent borrow checker from complaining
        mem::drop(interfaces);

        Ok(node)
    }

    /**
     * Register handler for a specific protocol.
     *
     * Inputs:
     * - protocol: the protocol for which a handler should be registered
     * - handler: the handler for the specific protocol.
     */
    pub fn register_handler(&self, protocol: u8, handler: Handler) {
        let mut handlers = self.handlers.lock().unwrap();
        handlers.insert(protocol, handler);
    }

    pub fn get_interfaces(&self) -> Arc<Mutex<Vec<NetworkInterface>>> {
        Arc::clone(&self.interfaces)
    }

    pub fn get_routing_table(&self) -> Arc<Mutex<RoutingTable>> {
        Arc::clone(&self.routing_table)
    }

    pub fn get_handlers(&self) -> Arc<Mutex<HashMap<u8, Handler>>> {
        Arc::clone(&self.handlers)
    }

    /**
     * Converts network interfaces into a human-readable string.
     */
    pub fn fmt_interfaces(&self) -> String {
        let mut res = String::new();
        let interfaces = self.interfaces.lock().unwrap();
        res.push_str("id\trem\t\tloc\n");
        for (index, interface) in interfaces.iter().enumerate() {
            if !interface.link_if.active {
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
            res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.gateway)));
            if index != routing_table.size() - 1 {
                res.push('\n');
            }
        }
        res
    }

    /**
     * Bring the link of an interface "down"
     */
    pub fn interface_link_down(&mut self, id: isize) -> Result<()> {
        let mut interfaces = self.interfaces.lock().unwrap();
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
        let id = id as usize;
        if !interfaces[id].link_if.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is down already", id),
            ));
        }
        interfaces[id].link_if.link_down();
        Ok(())
    }

    /**
     * Bring the link of an interface "up"
     */
    pub fn interface_link_up(&mut self, id: isize) -> Result<()> {
        let mut interfaces = self.interfaces.lock().unwrap();

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
        let id = id as usize;
        if interfaces[id].link_if.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is up already", id),
            ));
        }
        interfaces[id].link_if.link_up();
        Ok(())
    }

    /**
     * Send data to virtual-ip
     */
    pub fn send_data(&mut self, ip: String, protocol: usize, payload: String) -> Result<()> {
        if protocol != TEST_PROTOCOL.into() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("protocol {} is not valid, use 0 to send data", protocol),
            ));
        }
        let dst_addr = match str_2_ipv4(&ip) {
            Ok(ip) => ip,
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid address: {}", ip),
                ))
            }
        };
        let routing_table = self.routing_table.lock().unwrap();
        let interfaces = self.interfaces.lock().unwrap();
        let nexthop_addr = routing_table.get_route(&dst_addr)?.next_hop;
        let nexthop_if_index = in_interfaces(&nexthop_addr, &*interfaces);

        if nexthop_if_index < 0 {
            return Err(Error::new(ErrorKind::Other, "Destnation not reachable!"));
        }
        let nexthop_if_index = nexthop_if_index as usize;
        let nexthop_if = &interfaces[nexthop_if_index];

        send_test_message(nexthop_if, payload, nexthop_if.src_addr, dst_addr)?;
        Ok(())
    }
}

/**
 * Helper function to send route entries to a destination interface.
 */
fn send_route_entries(dst_if: &NetworkInterface, route_entries: Vec<RouteEntry>) {
    if !route_entries.is_empty() {
        let msg = RIPMessage::new(RIP_RESPONSE, route_entries.len() as u16, route_entries);
        // custom match since doesn't return
        match send_rip_message(dst_if, msg) {
            Ok(()) => (),
            Err(e) => eprintln!("{}", e),
        }
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
