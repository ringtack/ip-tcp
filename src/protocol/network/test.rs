use crate::protocol::network::rip::*;
use crate::protocol::network::{IPPacket, NetworkInterface, TEST_PROTOCOL};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/**
 * Sends a TEST message to the specified destination interface.
 */
pub fn send_test_message(
    dest_if: &NetworkInterface,
    msg: String,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> Result<()> {
    dest_if.send_ip(msg.as_bytes(), TEST_PROTOCOL, source, destination)
}

/**
 * Parses a TEST Message from a packet.
 */
pub fn recv_test_message(packet: &IPPacket) -> Result<String> {
    // Validate appropriate protocol
    if packet.header.protocol != TEST_PROTOCOL {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid protocol! Must be 0 (test).",
        ));
    }

    // decode
    let msg = String::from_utf8_lossy(packet.payload.as_slice()).into_owned();
    Ok(msg)
}

pub fn if_local(addr: &Ipv4Addr, interfaces: &[NetworkInterface]) -> bool {
    for net_if in interfaces.iter() {
        if net_if.src_addr == *addr {
            return true;
        }
    }
    false
}

pub fn make_test_handler(
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let interfaces = interfaces.lock().unwrap();

        let src_addr = Ipv4Addr::from(packet.header.source);
        let dst_addr = Ipv4Addr::from(packet.header.destination);
        let msg = recv_test_message(&packet)?;

        if if_local(&dst_addr, &*interfaces) {
            println!("got {} from {}", msg, src_addr);
        } else {
            let routing_table = routing_table.lock().unwrap();
            let nexthop_addr = routing_table.get_route(&dst_addr)?.next_hop;

            let nexthop_if_index = in_interfaces(&nexthop_addr, &*interfaces);
            if nexthop_if_index < 0 {
                return Err(Error::new(ErrorKind::Other, "Destnation not reachable!"));
            }
            let nexthop_if_index = nexthop_if_index as usize;
            let nexthop_if = &interfaces[nexthop_if_index];

            println!("[test: make_test_handler] transfered message");
            send_test_message(nexthop_if, msg, src_addr, dst_addr)?;
        }
        Ok(())
    }))
}
