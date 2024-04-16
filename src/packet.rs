/*
All communications inside of the domain protocol are carried in a single
format called a message.  The top level format of message is divided
into 5 sections (some of which are empty in certain cases) shown below:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

The header section is always present.  The header includes fields that
specify which of the remaining sections are present, and also specify
whether the message is a query or a response, a standard query or some
other opcode, etc.

The names of the sections after the header are derived from their use in
standard queries.  The question section contains fields that describe a
question to a name server.  These fields are a query type (QTYPE), a
query class (QCLASS), and a query domain name (QNAME).  The last three
sections have the same format: a possibly empty list of concatenated
resource records (RRs).  The answer section contains RRs that answer the
question; the authority section contains RRs that point toward an
authoritative name server; the additional records section contains RRs
which relate to the query, but are not strictly answers for the
question.
*/

use std::net::Ipv4Addr;

use crate::domain_name::DomainName;
use crate::header::DnsHeader;
use crate::question::{DnsQuestion, QueryClass, QueryType};
use crate::record::{DnsRecord, RecordClass, RecordType};
use bytes::{Buf, BufMut, BytesMut};

/// Whole DNS packet
#[derive(Debug, Clone, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
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
            let domain_name = DomainName::from_bytes(&mut buf);
            let query_type = QueryType::from(buf.get_u16());
            let class = QueryClass::from(buf.get_u16());

            let question = DnsQuestion::new(domain_name, query_type, class);
            questions.push(question);
        }

        // Answers
        let mut answers = vec![];
        for _i in 0..header.answer_entries {
            let domain_name = DomainName::from_bytes(&mut buf);
            let query_type = RecordType::from(buf.get_u16());
            let class = RecordClass::from(buf.get_u16());
            let ttl = buf.get_u32();
            let _length = buf.get_u16();
            let data = Ipv4Addr::new(buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8());

            let answer = DnsRecord::new(domain_name, query_type, class, ttl, data);
            answers.push(answer);
        }

        Self {
            header,
            questions,
            answers,
        }
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
                .expect("questions should not be empty if correct count was set");

            question.domain_name.write_bytes(&mut bp.buf);

            bp.buf.put_u16(QueryType::A.into());
            bp.buf.put_u16(QueryClass::IN.into());
        }

        // Answers
        for i in 0..dns_packet.header.answer_entries as usize {
            let answer = dns_packet
                .answers
                .get(i)
                .expect("answers should not be empty if correct count was set");

            answer.domain_name.write_bytes(&mut bp.buf);
            bp.buf.put_u16(QueryType::A.into());
            bp.buf.put_u16(QueryClass::IN.into());
            bp.buf.put_u32(answer.ttl);
            bp.buf.put_u16(answer.length);
            bp.buf.put(&answer.data.octets()[..]);
        }

        bp
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_dns_packet_to_bytes_packet_and_back() {
        let mut dns_packet = DnsPacket::new();
        dns_packet.header.id = 1234;
        dns_packet.header.response = true;
        dns_packet.header.truncated_message = true;
        dns_packet.header.recursion_available = true;
        dns_packet.header.rescode = crate::header::ResultCode::SERVFAIL;

        dns_packet.header.question_entries = 1;
        let domain_name = DomainName::from("codecrafters.io.");
        let dns_question = DnsQuestion::new(domain_name, QueryType::A, QueryClass::IN);
        dns_packet.questions.push(dns_question);

        dns_packet.header.answer_entries = 1;
        let domain_name = DomainName::from("codecrafters.io.");
        let dns_answer = DnsRecord::new(
            domain_name,
            RecordType::A,
            RecordClass::IN,
            3600,
            Ipv4Addr::new(127, 0, 0, 1),
        );
        dns_packet.answers.push(dns_answer);

        let bytes_packet = BytesPacket::from(dns_packet.clone());

        let parsed_dns_packet = DnsPacket::from(bytes_packet);

        assert_eq!(dns_packet, parsed_dns_packet);
    }
}
