use crate::protocol::network::rip::*;
use crate::protocol::network::{IPPacket, NetworkInterface};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
};

pub type Handler = fn(IPPacket) -> Result<(), Error>;

// TODO: REMOVE THIS IS JUST A TEST
fn rip_handler(packet: IPPacket) -> Result<(), Error> {
    let msg = recv_rip_message(&packet)?;
    println!("Message: {:?}", msg);
    Ok(())
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
    interfaces: Vec<NetworkInterface>,
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
    pub fn new_empty() -> Result<Node, Error> {
        Ok(Node {
            // src_link: LinkInterface::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?,
            interfaces: Vec::new(),
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
    pub fn new(linksfile: String) -> Result<Node, Error> {
        // Attempt to parse the linksfile
        match read_lines(&linksfile) {
            // if successful, create initial node
            Ok(lines) => {
                let mut node = Node::new_empty()?;
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
                            node.interfaces.push(NetworkInterface::new(
                                (index - 1) as u8,
                                src_addr,
                                dest_addr,
                                sock,
                                sock_addr,
                            )?);
                        }

                        // insert into routing table
                        node.insert_route(Route {
                            dst_addr: src_addr,
                            next_hop: src_addr,
                            cost: 0,
                            changed: false,
                        })
                    }
                }

                // TODO: REMOVE THIS IS JUST A TEST
                node.register_handler(200, rip_handler);

                thread::sleep(std::time::Duration::from_secs(2));

                // Send RIP Request to each of its net interfaces (i.e. neighbors)
                for dest_if in &node.interfaces {
                    let initial_route = RouteEntry::DUMMY_ROUTE;
                    let rip_msg = RIPMessage::new(RIP_REQUEST, 1, vec![initial_route]);
                    send_rip_message(dest_if, rip_msg)?;
                }

                // Initiate thread to listen for incoming packets
                // TODO: only one listener, or multiple?
                let (tx, rx) = channel::<IPPacket>();

                for net_if in &node.interfaces {
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
                        let curr_handlers = handlers.lock().unwrap();
                        if curr_handlers.contains_key(&protocol) {
                            (curr_handlers[&protocol])(packet);
                        }
                    }
                });

                Ok(node)
            }
            // otherwise, parsing error, so throw error
            Err(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid linksfile path: {}", linksfile),
            )),
        }
    }

    // pub fn listen_for_messages(&self) -> Result<(), Error> {
    // // TODO: error handling
    // thread::spawn(move || {
    // if let Some(rx) = &self.receiver {
    // for packet in rx {
    // let protocol = packet.header.protocol;
    // if self.handlers.contains_key(&protocol) {
    // (self.handlers[&protocol])(packet);
    // }
    // }
    // }
    // });

    // Ok(())
    // }

    /**
     * Wrapper function to concurrently insert (update) route from routing table.
     */
    pub fn insert_route(&mut self, route: Route) {
        let mut rt = self.routing_table.lock().unwrap();
        rt.insert(route);
    }

    /**
     * Register handler for a specific protocol.
     *
     * Inputs:
     * - protocol: the protocol for which a handler should be registered
     * - handler: the handler for the specific protocol.
     */
    pub fn register_handler(&mut self, protocol: u8, handler: Handler) {
        let mut handlers = self.handlers.lock().unwrap();
        handlers.insert(protocol, handler);
    }

    /**
     * Converts network interfaces into a human-readable string.
     */
    pub fn fmt_interfaces(&self) -> String {
        let mut res = String::new();
        res.push_str("id\trem\t\tloc\n");
        for (index, interface) in self.interfaces.iter().enumerate() {
            if !interface.link_if.active {
                continue;
            }
            res.push_str(
                &(format!(
                    "{}\t{}\t{}",
                    interface.id, interface.dst_addr, interface.src_addr
                )),
            );
            if index != self.interfaces.len() - 1 {
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
        let routing_table = self.routing_table.lock().unwrap();

        for (index, (_, route)) in routing_table.iter().enumerate() {
            res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.next_hop)));
            if index != self.interfaces.len() - 1 {
                res.push('\n');
            }
        }
        res
    }

    /**
     * Bring the link of an interface "down"
     */
    pub fn interface_link_down(&mut self, id: isize) -> Result<(), Error> {
        if id < 0 || id as usize >= self.interfaces.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "interface {} out of bounds : (0 to {})",
                    id,
                    self.interfaces.len()
                ),
            ));
        }
        let id = id as usize;
        if !self.interfaces[id].link_if.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is down already", id),
            ));
        }
        self.interfaces[id].link_if.active = false;
        Ok(())
    }

    /**
     * Bring the link of an interface "up"
     */
    pub fn interface_link_up(&mut self, id: isize) -> Result<(), Error> {
        if id < 0 || id as usize >= self.interfaces.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "interface {} out of bounds : (0 to {})",
                    id,
                    self.interfaces.len()
                ),
            ));
        }
        let id = id as usize;
        if self.interfaces[id].link_if.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is up already", id),
            ));
        }
        self.interfaces[id].link_if.active = true;
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
