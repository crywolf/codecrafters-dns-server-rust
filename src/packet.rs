use bytes::{Buf, BufMut, BytesMut};

use crate::header::{DnsHeader, ResultCode};

/// Whole DNS packet
#[derive(Debug, Clone, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
        }
    }
}

impl From<BytesPacket> for DnsPacket {
    ///                                  1  1  1  1  1  1
    ///    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                      ID                       |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    QDCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    ANCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    NSCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    ARCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    fn from(value: BytesPacket) -> Self {
        let mut buf = value.buf;

        let mut header = DnsHeader::new();
        header.id = buf.get_u16();

        let flags = buf.get_u16();
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        header.response = (a & (1 << 7)) > 0;
        header.opcode = (a >> 3) & 0x0F;
        header.authoritative_answer = (a & (1 << 2)) > 0;
        header.truncated_message = (a & (1 << 1)) > 0;
        header.recursion_desired = (a & (1 << 0)) > 0;

        header.recursion_available = (b & (1 << 7)) > 0;
        header.z = (b & (1 << 6)) > 0;
        header.rescode = ResultCode::from_num(b & 0x0F);

        header.question_entries = buf.get_u16();
        header.answer_entries = buf.get_u16();
        header.authoritative_entries = buf.get_u16();
        header.additional_entries = buf.get_u16();

        Self { header }
    }
}

//////////////////////////////////////////////////////////////////////////////

/// Binary representation of DNS packet
pub struct BytesPacket {
    pub buf: BytesMut,
}

impl BytesPacket {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(512),
        }
    }
}

impl From<DnsPacket> for BytesPacket {
    ///                                  1  1  1  1  1  1
    ///    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                      ID                       |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    QDCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    ANCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    NSCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///  |                    ARCOUNT                    |
    ///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    fn from(value: DnsPacket) -> Self {
        let mut bp = BytesPacket::new();

        let header = value.header;
        bp.buf.put_u16(header.id);

        let a: u8 = (header.response as u8) << 7
            | (header.opcode << 3)
            | (header.authoritative_answer as u8) << 2
            | (header.truncated_message as u8) << 1
            | (header.recursion_desired as u8);

        let b: u8 = (header.recursion_available as u8) << 7
            | (header.z as u8) << 6
            | (header.rescode as u8);

        let flags = (a as u16) << 8 | (b as u16);
        bp.buf.put_u16(flags);

        bp.buf.put_u16(header.question_entries);
        bp.buf.put_u16(header.answer_entries);
        bp.buf.put_u16(header.authoritative_entries);
        bp.buf.put_u16(header.additional_entries);

        bp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_packet_to_bytes_packet_and_back() {
        let mut dns_packet = DnsPacket::new();
        dns_packet.header.id = 1234;
        dns_packet.header.response = true;
        dns_packet.header.truncated_message = true;
        dns_packet.header.recursion_available = true;
        dns_packet.header.rescode = crate::header::ResultCode::SERVFAIL;
        dns_packet.header.authoritative_entries = 6;

        let bytes_packet = BytesPacket::from(dns_packet.clone());

        let parsed_dns_packet = DnsPacket::from(bytes_packet);

        assert_eq!(dns_packet, parsed_dns_packet);
    }
}
