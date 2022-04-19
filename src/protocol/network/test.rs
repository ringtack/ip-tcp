use crate::protocol::network::*;

use etherparse::Ipv4Header;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;

pub const TEST_PROTOCOL: u8 = 0;
/*
 * Sends a TEST message to the specified destination interface.
 */
// pub fn send_test_message(
// dest_if: &NetworkInterface,
// msg: String,
// source: Ipv4Addr,
// destination: Ipv4Addr,
// ) -> Result<()> {
// dest_if.send_packet_raw(msg.as_bytes(), TEST_PROTOCOL, source, destination)
// }

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

pub fn make_test_handler(interfaces: Arc<NetworkInterfaces>) -> Handler {
    Arc::new(Mutex::new(move |packet: IPPacket| -> Result<()> {
        let (header, msg) = recv_test_message(&packet)?;

        let dst_addr = Ipv4Addr::from(header.destination);

        if let Some(net_if) = interfaces.get_local_if(&dst_addr) {
            println!("{}", fmt_test_msg(msg, &header, net_if));
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                format!("Gateway interface with address {} is missing.", dst_addr),
            ))
        }
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
