use crate::protocol::network::rip::Route;
use crate::protocol::network::rip::RoutingTable;
use crate::protocol::network::NetworkInterface;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Error, ErrorKind};
use std::net;
use std::path::Path;

pub struct Node {
    src_addr: net::SocketAddrV4,
    interfaces: Vec<NetworkInterface>,
    routing_table: RoutingTable,
}
impl Node {
    pub fn empty() -> Node {
        Node {
            src_addr: net::SocketAddrV4::new(net::Ipv4Addr::UNSPECIFIED, 0),
            interfaces: Vec::new(),
            routing_table: RoutingTable::new(),
        }
    }

    pub fn new(linksfile: String) -> Result<Node, Error> {
        match read_lines(&linksfile) {
            Ok(lines) => {
                let mut node = Node::empty();
                for (index, line) in lines.enumerate() {
                    if let Ok(line) = line {
                        if index == 0 {
                            let line: Vec<&str> = line.split_whitespace().collect();
                            node.src_addr = net::SocketAddrV4::new(
                                str_2_ipv4(line[0]),
                                line[1].parse::<u16>().unwrap(),
                            );
                            continue;
                        }
                        let line: Vec<&str> = line.split_whitespace().collect();
                        let dest_addr = str_2_ipv4(line[3]);
                        node.interfaces.push(NetworkInterface::new(
                            (index - 1) as u8,
                            str_2_ipv4(line[2]),
                            dest_addr,
                            net::SocketAddrV4::new(
                                str_2_ipv4(line[0]),
                                line[1].parse::<u16>().unwrap(),
                            ),
                        )?);
                        node.routing_table.insert(Route {
                            dst_addr: dest_addr,
                            next_hop: dest_addr,
                            cost: 1,
                            changed: false,
                        })
                    }
                }
                Ok(node)
            }
            Err(e) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid linksfile path: {}", linksfile),
            )),
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn str_2_ipv4(s: &str) -> net::Ipv4Addr {
    if s == "localhost" {
        net::Ipv4Addr::LOCALHOST
    } else {
        let s: Vec<u8> = s.split(".").map(|x| x.parse::<u8>().unwrap()).collect();
        net::Ipv4Addr::new(s[0], s[1], s[2], s[3])
    }
}
