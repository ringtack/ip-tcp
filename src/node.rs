use crate::protocol::network::rip::*;
use crate::protocol::network::{IPPacket, NetworkInterface};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, Error, ErrorKind, Result},
    mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
};

pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

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
// pub struct Node<T>
// where
// T: FnMut(IPPacket) -> Result<(), Error>,
pub struct Node {
    // interfaces: Vec<NetworkInterface>,
    // routing_table: RoutingTable,
    // handlers: HashMap<u8, Handler>,
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    handlers: Arc<Mutex<HashMap<u8, Handler>>>,
}

// impl<T> Node<T>
// where
// T: FnMut(IPPacket) -> Result<(), Error>,
impl Node {
    /**
     * Creates an empty node.
     *
     * Returns:
     * - A Result<Node, Error> with a default node, or error.
     */
    pub fn new_empty() -> Result<Node> {
        Ok(Node {
            // interfaces: Vec::new(),
            // routing_table: RoutingTable::new(),
            // handlers: HashMap::new(),
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
    pub fn new(linksfile: String, default_handlers: Vec<Handler>) -> Result<Node> {
        // Attempt to parse the linksfile
        match read_lines(&linksfile) {
            // if successful, create initial node
            Ok(lines) => {
                // let node = Arc::new(Mutex::new(Node::new_empty()?));
                let node = Node::new_empty()?;

                // let mut node_guard = node.lock().unwrap();
                let mut interfaces = node.interfaces.lock().unwrap();
                // store src socket; shared across all interfaces
                let mut src_sock: Option<UdpSocket> = None;

                // iterate through every line
                for (index, line) in lines.enumerate() {
                    if let Ok(line) = line {
                        let line: Vec<&str> = line.split_whitespace().collect();
                        // regardless of source or dest, gets addr:port
                        let sock_addr =
                            SocketAddrV4::new(str_2_ipv4(line[0]), line[1].parse::<u16>().unwrap());

                        // if first line, is source "L2 address"
                        if index == 0 {
                            // Create socket on which node will listen
                            println!("[Node::new] Listening on {}...", sock_addr);

                            src_sock = Some(UdpSocket::bind(sock_addr)?);
                            continue;
                        }

                        // otherwise, make network interface:
                        //      <Dest L2 Address> <Dest L2 Port> <Src IF> <Dest IF>
                        let src_addr = str_2_ipv4(line[2]);
                        let dest_addr = str_2_ipv4(line[3]);

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
                        // routing_table.insert(Route {
                        // dst_addr: src_addr,
                        // next_hop: src_addr,
                        // cost: 0,
                        // changed: false,
                        // mask: INIT_MASK,
                        // });
                        insert_route(
                            Arc::clone(&node.routing_table),
                            Route {
                                dst_addr: src_addr,
                                next_hop: src_addr,
                                cost: 0,
                                changed: false,
                                mask: INIT_MASK,
                            },
                        )
                    }
                }

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

                // TODO: REMOVE THIS IS JUST A TEST
                let mut handlers = node.handlers.lock().unwrap();
                handlers.insert(200, Arc::clone(&default_handlers[0]));
                mem::drop(handlers);
                thread::sleep(std::time::Duration::from_secs(2));

                // Send RIP Request to each of its net interfaces (i.e. neighbors)
                for dest_if in &*interfaces {
                    let initial_route = RouteEntry::DUMMY_ROUTE;
                    let rip_msg = RIPMessage::new(RIP_REQUEST, 1, vec![initial_route]);
                    send_rip_message(dest_if, rip_msg)?;
                }

                // Finally, infinitely process incoming messages
                // TODO: store result somewhere
                let handlers = Arc::clone(&node.handlers);
                // let node_cp = Arc::clone(&node);
                thread::spawn(move || {
                    for packet in rx {
                        let protocol = packet.header.protocol;
                        // let node = node_cp.lock().unwrap();
                        let handlers = handlers.lock().unwrap();
                        if handlers.contains_key(&protocol) {
                            let mut handler = handlers[&protocol].lock().unwrap();
                            match (handler)(packet) {
                                Ok(()) => (),
                                Err(e) => println!("{}", e),
                            }
                        }
                    }
                });

                // unlock before returning to prevent borrow checker from complaining
                // mem::drop(node_guard);
                mem::drop(interfaces);

                Ok(node)
            }
            // otherwise, parsing error, so throw error
            Err(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid linksfile path: {}", linksfile),
            )),
        }
    }

    /**
     * Register handler for a specific protocol.
     *
     * Inputs:
     * - protocol: the protocol for which a handler should be registered
     * - handler: the handler for the specific protocol.
     */
    // pub fn register_handler(&mut self, protocol: u8, handler: Handler) {
    // self.handlers.insert(protocol, handler);
    // }

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
        let interfaces = self.interfaces.lock().unwrap();
        let routing_table = self.routing_table.lock().unwrap();

        for (index, (_, route)) in routing_table.iter().enumerate() {
            res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.next_hop)));
            if index != interfaces.len() - 1 {
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
        interfaces[id].link_if.active = false;
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
        interfaces[id].link_if.active = true;
        Ok(())
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
fn str_2_ipv4(s: &str) -> Ipv4Addr {
    if s == "localhost" {
        Ipv4Addr::LOCALHOST
    } else {
        let s: Vec<u8> = s.split('.').map(|x| x.parse::<u8>().unwrap()).collect();
        Ipv4Addr::new(s[0], s[1], s[2], s[3])
    }
}

// pub fn rip_handler(node: Arc<Mutex<Node>>, packet: IPPacket) -> Result<(), Error> {
// // get source IP address
// let src_addr = Ipv4Addr::from(packet.header.source);

// println!("In RIP handler; packet from {}...", src_addr);

// let node = node.lock().unwrap();
// // check that source addr is one of the destination addresses
// let src_if_index = in_interfaces(&src_addr, &node.interfaces);

// println!("src if index: {}", src_if_index);

// if src_if_index < 0 {
// return Err(Error::new(
// ErrorKind::Other,
// "Source address not from reachable interface!",
// ));
// }
// let src_if_index = src_if_index as usize;

// // first, attempt to parse into rip message
// let msg = recv_rip_message(&packet)?;

// println!("RIP Message: {:?}", msg);

// // Handle Request
// if msg.command == RIP_REQUEST {
// match msg.num_entries {
// // if no entries, do nothing
// 0 => return Ok(()),
// // if 1 entry, check that entry is default
// 1 => {
// if msg.entries[0] != RouteEntry::DUMMY_ROUTE {
// return Err(Error::new(
// ErrorKind::Other,
// "RIP requests must have 1 entry with a default route.",
// ));
// }

// println!("in here 1");

// // for each entry in the routing table, add to RIP message
// let mut entries: Vec<RouteEntry> =
// Vec::<RouteEntry>::with_capacity(node.routing_table.size());
// for (dst_addr, entry) in node.routing_table.iter() {
// println!("in here 2");

// // if next hop is same as source, poison it
// let cost = if entry.next_hop == src_addr {
// INFINITY
// } else {
// entry.cost as u32
// };

// // turn entry into route
// let route_entry = RouteEntry {
// cost,
// address: u32::from_be_bytes(dst_addr.octets()),
// mask: entry.mask,
// };

// entries.push(route_entry);
// }
// // make new RIP message
// let msg = RIPMessage {
// command: RIP_RESPONSE,
// num_entries: entries.len() as u16,
// entries,
// };

// println!("Sending {:?}...", msg);

// // send message response!
// return send_rip_message(&node.interfaces[src_if_index], msg);
// }
// // if more than 1 entry, do nothing
// _ => {
// return Err(Error::new(
// ErrorKind::Other,
// "RIP requests with more than 1 entry are not currently supported.",
// ))
// }
// }
// } else if msg.command == RIP_RESPONSE {
// return Ok(());
// }

// Ok(())
// }
