use etherparse::{IpNumber, Ipv4Header};
use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
};

/**
 * IP Packet.
 */
pub struct IPPacket {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

impl IPPacket {
    /**
     * Creates a new IP Packet.
     *
     * Inputs:
     * - source: the IP Address the packet will is sent from
     * - destination: the IP Address the packet will be sent to
     * - payload: the payload of the packet
     * - ttl: time to live (usually default = 16)
     *
     * Returns:
     * - an IP Packet!
     */

    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: Vec<u8>,
        ttl: u8,
        protocol: u8,
    ) -> IPPacket {
        let mut packet = IPPacket {
            header: Ipv4Header::new(
                payload.len() as u16,
                ttl,
                IpNumber::IPv4,
                source.octets(),
                destination.octets(),
            ),
            payload,
        };

        // enable fragmenting
        packet.header.dont_fragment = false;
        // set protocol to specified protocol
        packet.header.protocol = protocol;
        // compute checksum
        packet.header.header_checksum = packet.header.calc_header_checksum().unwrap();

        packet
    }

    /**
     * Computes the size of the IP Packet.
     */
    pub fn size(&self) -> usize {
        (self.header.ihl() * 4) as usize + self.header.payload_len as usize
    }

    /**
     * Convert IP Packet to a byte vector.
     *
     * Returns:
     * - a byte representation of an IP Packet, or an Error
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // convert packet into bytes
        let mut header_bytes = Vec::<u8>::with_capacity(self.header.header_len());
        // need custom check to convert to correct error type; this computes checksum!
        if let Err(e) = self.header.write(&mut header_bytes) {
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }

        // combine into one byte vector
        header_bytes.extend(self.payload.to_vec());
        Ok(header_bytes)
        // Ok([header_bytes.as_slice(), self.payload.as_slice()].concat())
    }

    /**
     * Converts a byte slice into an IP Packet, if possible.
     *
     * Returns:
     * - The IPPacket, or an Error (e.g. if checksum invalid)
     */
    pub fn from_bytes(buf: &[u8], num_bytes: usize) -> Result<IPPacket> {
        // custom handling (since from_slice gives a weird error :/)
        match Ipv4Header::from_slice(buf) {
            Ok((header, buf)) => {
                // checksum validation
                if header.calc_header_checksum().unwrap() != header.header_checksum {
                    println!("checksum validation failed");

                    return Err(Error::new(ErrorKind::Other, "checksum validation failed"));
                }

                // subtract number of bytes read into header from remaining bytes
                let num_bytes = num_bytes - (header.ihl() * 4) as usize;
                // get IP payload from L2 payload
                let mut payload = Vec::<u8>::with_capacity(num_bytes);
                payload.extend_from_slice(&buf[..num_bytes]);
                // return packet
                Ok(IPPacket { header, payload })
            }
            Err(e) => {
                println!("Failed to convert packet to slice");
                Err(Error::new(ErrorKind::Other, e.to_string()))
            }
        }
    }
}
