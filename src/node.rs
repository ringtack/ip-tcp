use crate::protocol::link::LinkInterface;
use crate::protocol::network::rip::{RIPMessage, Route, RoutingTable, DUMMY_ROUTE};
use crate::protocol::network::NetworkInterface;
use std::{
    fs::File,
    io::{self, BufRead, Error, ErrorKind},
    mem,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    slice,
};

/**
 * Structure for a Node on the Network.
 *
 * Fields:
 * - src_link: the link interface of the current node. Same for all interfaces.
 * - interfaces: network interfaces for each of the node's connections.
 * - routing_table: dynamically updating table for routes.
 */
pub struct Node {
    src_link: LinkInterface,
    interfaces: Vec<NetworkInterface>,
    routing_table: RoutingTable,
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
            src_link: LinkInterface::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?,
            interfaces: Vec::new(),
            routing_table: RoutingTable::new(),
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
                // iterate through every line
                for (index, line) in lines.enumerate() {
                    if let Ok(line) = line {
                        let line: Vec<&str> = line.split_whitespace().collect();
                        // regardless of source or dest, gets addr:port
                        let sock_addr =
                            SocketAddrV4::new(str_2_ipv4(line[0]), line[1].parse::<u16>().unwrap());

                        // if first line, is source "L2 address"
                        if index == 0 {
                            node.src_link = LinkInterface::new(sock_addr)?;
                            continue;
                        }

                        // otherwise, make network interface:
                        //      <Dest L2 Address> <Dest L2 Port> <Src IF> <Dest IF>
                        let src_addr = str_2_ipv4(line[2]);
                        let dest_addr = str_2_ipv4(line[3]);
                        node.interfaces.push(NetworkInterface::new(
                            (index - 1) as u8,
                            src_addr,
                            node.src_link.clone(),
                            dest_addr,
                            sock_addr,
                        )?);
                        // insert into routing table
                        node.routing_table.insert(Route {
                            dst_addr: src_addr,
                            next_hop: src_addr,
                            cost: 0,
                            changed: false,
                        })
                    }
                }

                // finally, send RIP Request to each of its net interfaces (i.e. neighbors)
                for dest_if in &node.interfaces {
                    let initial_route = DUMMY_ROUTE;
                    let rip_msg = RIPMessage::new(1, 1, vec![initial_route]);
                    node.send_rip_message(dest_if, rip_msg)?;
                }
                Ok(node)
            }
            Err(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid linksfile path: {}", linksfile),
            )),
        }
    }

    /**
     * Sends a RIP message to the specified destination interface.
     *
     * Inputs:
     * - dest_if: where to send RIP message
     * - msg: the RIP message
     *
     * Returns:
     * - A Result<(), Error> with nothing, or an error
     */
    pub fn send_rip_message(
        &self,
        dest_if: &NetworkInterface,
        msg: RIPMessage,
    ) -> Result<(), Error> {
        // obtain raw pointer to data
        let p: *const RIPMessage = &msg;
        // convert between pointer types (to u8)
        let p: *const u8 = p as *const u8;
        // interpret as slice
        let payload: &[u8] = unsafe { slice::from_raw_parts(p, mem::size_of::<RIPMessage>()) };
        dest_if.send_ip(payload)
    }

    /**
     * Converts network interfaces into a human-readable string.
     */
    pub fn fmt_interfaces(&self) -> String {
        let mut res = String::new();
        res.push_str("id\trem\t\tloc\n");
        for (index, interface) in self.interfaces.iter().enumerate() {
            if !interface.dst_link.active {
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
        for (index, (_, route)) in self.routing_table.iter().enumerate() {
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
        if !self.interfaces[id].dst_link.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is down already", id),
            ));
        }
        self.interfaces[id].dst_link.active = false;
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
        if self.interfaces[id].dst_link.active {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("interface {} is up already", id),
            ));
        }
        self.interfaces[id].dst_link.active = true;
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
