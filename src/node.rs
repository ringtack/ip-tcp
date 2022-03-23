use crate::protocol::network::rip::*;
use crate::protocol::network::{IPPacket, NetworkInterface, RIP_PROTOCOL, TEST_PROTOCOL};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, Error, ErrorKind, Result},
    mem,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
    time::Duration,
};

pub type Handler = Arc<Mutex<dyn FnMut(IPPacket) -> Result<()> + Send>>;

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
        match read_lines(&linksfile) {
            // if successful, create initial node
            Ok(lines) => {
                let node = Node::new_empty()?;

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
                        insert_route(
                            Arc::clone(&node.routing_table),
                            Route {
                                dst_addr: src_addr,
                                gateway: src_addr,
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

                // Configure handlers
                let mut handlers = node.handlers.lock().unwrap();
                // add any default handlers provided
                for ph in default_handlers {
                    handlers.insert(ph.protocol, Arc::clone(&ph.handler));
                }
                // TODO: register test handler
                // handlers.insert(...);
                // register rip handler
                handlers.insert(
                    RIP_PROTOCOL,
                    make_rip_handler(
                        Arc::clone(&node.interfaces),
                        Arc::clone(&node.routing_table),
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
                thread::spawn(move || loop {
                    thread::sleep(Duration::from_secs(UPDATE_TIME)); // update every 5 seconds

                    let routing_table = rt.lock().unwrap();
                    let interfaces = ifs.lock().unwrap();
                    // for each network interface:
                    for dest_if in &*interfaces {
                        // get processed route entries; need match since this doesn't return
                        match routing_table.get_entries(dest_if) {
                            Ok(route_entries) => {
                                let msg = RIPMessage::new(
                                    RIP_RESPONSE,
                                    route_entries.len() as u16,
                                    route_entries,
                                );
                                // custom match since doesn't return
                                match send_rip_message(dest_if, msg) {
                                    Ok(()) => (),
                                    Err(e) => eprintln!("{}", e),
                                }
                            }
                            Err(e) => eprintln!("{}", e),
                        };
                    }
                });

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
