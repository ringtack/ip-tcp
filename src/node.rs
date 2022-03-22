use crate::protocol::link::LinkInterface;
use crate::protocol::network::rip::{RIPMessage, Route, RouteEntry, RoutingTable};
use crate::protocol::network::{NetworkInterface, RIP_PROTOCOL, TEST_PROTOCOL};
use std::{
    fs::File,
    io::{self, BufRead, Error, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
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
    pub fn empty() -> Result<Node, Error> {
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
                let mut node = Node::empty()?;
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
                    let initial_route = RouteEntry::DUMMY_ROUTE;
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
        let payload = msg.to_bytes();
        dest_if.send_ip(payload.as_slice(), RIP_PROTOCOL)
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
