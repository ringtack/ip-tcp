use etherparse::TcpHeader;
use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddrV4,
};

#[derive(Clone)]
pub struct TCPSegment {
    pub header: TcpHeader,
    pub data: Vec<u8>,
}

impl TCPSegment {
    /**
     * Creates a new TCP segment from the source socket to the destination socket. Sets only the
     * ACK control flag.
     */
    pub fn new(
        src_sock: SocketAddrV4,
        dst_sock: SocketAddrV4,
        seq_no: u32,
        ack_no: u32,
        win_size: u16,
        data: Vec<u8>,
    ) -> TCPSegment {
        let mut packet = TCPSegment {
            header: TcpHeader::new(src_sock.port(), dst_sock.port(), seq_no, win_size),
            data,
        };
        // set ACK fields
        packet.header.acknowledgment_number = ack_no;
        packet.header.ack = true;

        // compute checksum
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(src_sock.ip().octets(), dst_sock.ip().octets(), &packet.data)
            .unwrap();

        packet
    }

    /**
     * Creates a new TCP SYN segment. Sets only the SYN control flag.
     */
    pub fn new_syn(src_sock: SocketAddrV4, dst_sock: SocketAddrV4, isn: u32) -> TCPSegment {
        let mut packet = TCPSegment {
            header: TcpHeader::new(src_sock.port(), dst_sock.port(), isn, 0),
            data: Vec::new(),
        };
        // mark as SYN packet
        packet.header.syn = true;

        // compute checksum TODO: error check
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(src_sock.ip().octets(), dst_sock.ip().octets(), &packet.data)
            .unwrap();

        packet
    }

    /**
     * Creates a new TCP SYN+ACK segment. Sets both SYN and ACK.
     */
    pub fn new_syn_ack(
        src_sock: SocketAddrV4,
        dst_sock: SocketAddrV4,
        seq_no: u32,
        ack_no: u32,
        win_sz: u16,
    ) -> TCPSegment {
        let mut packet = TCPSegment {
            header: TcpHeader::new(src_sock.port(), dst_sock.port(), seq_no, win_sz),
            data: Vec::new(),
        };
        // mark as SYN+ACK packet
        packet.header.syn = true;
        packet.header.ack = true;
        packet.header.acknowledgment_number = ack_no;

        // compute checksum TODO: error check
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(src_sock.ip().octets(), dst_sock.ip().octets(), &packet.data)
            .unwrap();

        packet
    }

    /**
     * Creates a new TCP FIN segment. Sets the FIN+ACK control flag.
     */
    pub fn new_fin(
        src_sock: SocketAddrV4,
        dst_sock: SocketAddrV4,
        seq_no: u32,
        ack_no: u32,
        win_sz: u16,
    ) -> TCPSegment {
        let mut packet = TCPSegment {
            header: TcpHeader::new(src_sock.port(), dst_sock.port(), seq_no, win_sz),
            data: Vec::new(),
        };
        // mark as FIN segment
        packet.header.ack = true;
        packet.header.fin = true;
        packet.header.acknowledgment_number = ack_no;

        // compute checksum TODO: error check
        packet.header.checksum = packet
            .header
            .calc_checksum_ipv4_raw(src_sock.ip().octets(), dst_sock.ip().octets(), &packet.data)
            .unwrap();

        packet
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // convert packet into bytes
        let mut header_bytes = Vec::<u8>::with_capacity(self.header.header_len() as usize);
        // need custom check to convert to correct error type; checksum NOT computed!
        if let Err(e) = self.header.write(&mut header_bytes) {
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }

        // combine into one byte vector
        header_bytes.extend(self.data.to_vec());
        Ok(header_bytes)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<TCPSegment> {
        // custom handling (since from_slice gives a weird error :/)
        match TcpHeader::from_slice(buf) {
            // checksum validation must occur later, since needs Ipv4Header
            Ok((header, buf)) => {
                // subtract number of bytes read into header from remaining bytes
                let num_bytes = buf.len();
                // get data from segment
                let mut data = Vec::<u8>::with_capacity(num_bytes);
                data.extend_from_slice(&buf[..num_bytes]);
                // return segment
                Ok(TCPSegment { header, data })
            }
            Err(e) => {
                println!("Failed to convert packet to slice");
                Err(Error::new(ErrorKind::Other, e.to_string()))
            }
        }
    }
}
