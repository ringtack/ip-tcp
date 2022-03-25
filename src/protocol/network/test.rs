use crate::protocol::network::rip::*;
use crate::protocol::network::*;
use etherparse::Ipv4Header;
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
pub fn recv_test_message(packet: &IPPacket) -> Result<(Ipv4Header, String)> {
    // Validate appropriate protocol
    if packet.header.protocol != TEST_PROTOCOL {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid protocol! Must be 0 (test).",
        ));
    }

    // decode
    let msg = String::from_utf8_lossy(packet.payload.as_slice()).into_owned();
    Ok((packet.header.clone(), msg))
}

pub fn make_test_handler(
    interfaces: Arc<Mutex<Vec<NetworkInterface>>>,
    routing_table: Arc<Mutex<RoutingTable>>,
) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let interfaces = interfaces.lock().unwrap();

        let src_addr = Ipv4Addr::from(packet.header.source);
        let dst_addr = Ipv4Addr::from(packet.header.destination);
        let (header, msg) = recv_test_message(&packet)?;

        // if destination is local interface, just print
        if let Some(index) = if_local(&dst_addr, &*interfaces) {
            println!("{}", fmt_test_msg(msg, &header, &interfaces[index]));
        } else {
            // otherwise, search routing table
            let routing_table = routing_table.lock().unwrap();

            // check if one of the destinations
            if !routing_table.has_dst(&dst_addr) {
                return Err(Error::new(
                    ErrorKind::Other,
                    "[Route] Destination not reachable!",
                ));
            }

            let gateway_addr = routing_table.get_route(&dst_addr)?.gateway;
            // ensure that gateway is actually a local interface
            if let Some(gateway_if_index) = if_local(&gateway_addr, &*interfaces) {
                let nexthop_if = &interfaces[gateway_if_index];

                // println!("[test: make_test_handler] transfered message");
                send_test_message(nexthop_if, msg, src_addr, dst_addr)?;
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "[Link] Destination not reachable!",
                ));
            }
        }
        Ok(())
    }))
}

/**
 * Pretty-prints a test message.
 */
fn fmt_test_msg(msg: String, header: &Ipv4Header, net_if: &NetworkInterface) -> String {
    let mut res = String::from("----------Node received packet!----------\n");
    // format da packet
    res.push_str(&(format!("\tarrived link\t: {}\n", net_if.id)));
    res.push_str(&(format!("\tsource IP\t: {}\n", Ipv4Addr::from(header.source))));
    res.push_str(
        &(format!(
            "\tdestination IP\t: {}\n",
            Ipv4Addr::from(header.destination)
        )),
    );
    res.push_str(&(format!("\tprotocol\t: {}\n", header.protocol)));
    res.push_str(&(format!("\tpayload length\t: {}\n", header.payload_len)));
    res.push_str(&(format!("\tpayload\t\t: {}\n", &msg)));
    res.push_str("------------------------------------------\n");

    res
}
