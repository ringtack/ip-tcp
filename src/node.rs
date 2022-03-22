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

pub struct Node {
    src_link: LinkInterface,
    interfaces: Vec<NetworkInterface>,
    routing_table: RoutingTable,
}
impl Node {
    pub fn empty() -> Result<Node, Error> {
        Ok(Node {
            src_link: LinkInterface::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?,
            interfaces: Vec::new(),
            routing_table: RoutingTable::new(),
        })
    }

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
                    // net_if.send_rip_request()
                }
                Ok(node)
            }
            Err(_) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid linksfile path: {}", linksfile),
            )),
        }
    }

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
                res.push_str("\n");
            }
        }
        res
    }

    pub fn fmt_routes(&self) -> String {
        let mut res = String::new();
        res.push_str("cost\tdst\t\tloc\n");
        for (index, (_, route)) in self.routing_table.iter().enumerate() {
            res.push_str(&(format!("{}\t{}\t{}", route.cost, route.dst_addr, route.next_hop)));
            if index != self.interfaces.len() - 1 {
                res.push_str("\n");
            }
        }
        res
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn str_2_ipv4(s: &str) -> Ipv4Addr {
    if s == "localhost" {
        Ipv4Addr::LOCALHOST
    } else {
        let s: Vec<u8> = s.split(".").map(|x| x.parse::<u8>().unwrap()).collect();
        Ipv4Addr::new(s[0], s[1], s[2], s[3])
    }
}
