use crate::header::DnsHeader;
use crate::question::{DnsQuestion, QueryClass, QueryType};
use bytes::{Buf, BufMut, BytesMut};

/// Whole DNS packet
#[derive(Debug, Clone, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
        }
    }
}

impl From<BytesPacket> for DnsPacket {
    fn from(bytes_packet: BytesPacket) -> Self {
        let mut buf = bytes_packet.buf;

        // Header
        let mut header = DnsHeader::new();
        header.read_bytes(&mut buf);

        // Questions
        let mut questions = vec![];
        for _i in 0..header.question_entries {
            let mut domain_name = String::new();

            loop {
                // length of label
                let len = buf.get_u8();

                if len == 0 {
                    // end of domain name
                    break;
                }

                for _i in 0..len {
                    // read one label
                    domain_name.push(buf.get_u8() as char);
                }
                domain_name.push('.');
            }

            let query_type = QueryType::from(buf.get_u16());
            let class = QueryClass::from(buf.get_u16());

            let question = DnsQuestion::new(domain_name, query_type, class);
            questions.push(question);
        }

        Self { header, questions }
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
    fn from(dns_packet: DnsPacket) -> Self {
        let mut bp = BytesPacket::new();

        // Header
        dns_packet.header.write_bytes(&mut bp.buf);

        // Questions
        for i in 0..dns_packet.header.question_entries as usize {
            let question = dns_packet
                .questions
                .get(i)
                .expect("questions should not be empty if, correct count was set");

            for label in question.domain_name.split('.') {
                let len = label.len() as u8;
                bp.buf.put_u8(len);
                bp.buf.put(label.as_bytes());
            }
        }

        bp.buf.put_u16(QueryType::A.into());
        bp.buf.put_u16(QueryClass::IN.into());

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

        dns_packet.header.question_entries = 1;
        let domain_name = String::from("codecrafters.io.");
        let dns_question = DnsQuestion::new(domain_name, QueryType::A, QueryClass::IN);
        dns_packet.questions.push(dns_question);

        let bytes_packet = BytesPacket::from(dns_packet.clone());

        let parsed_dns_packet = DnsPacket::from(bytes_packet);

        assert_eq!(dns_packet, parsed_dns_packet);
    }
}
