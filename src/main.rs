use anyhow::Result;
use std::net::UdpSocket;

use crate::{
    header::ResponseCode,
    packet::{BytesPacket, DnsPacket},
    question::DnsQuestion,
    record::DnsRecord,
};

mod domain_name;
mod header;
mod packet;
mod question;
mod record;

fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let mut bp = BytesPacket::new();
                bp.buf.extend_from_slice(&buf);
                let received = DnsPacket::from(bp);
                println!("Received DNS packet: {:#?}", received);

                // Response
                let mut response = DnsPacket::new();
                response.header.id = received.header.id;
                response.header.response = true;
                response.header.question_entries = 1;
                response.header.opcode = received.header.opcode;
                response.header.recursion_desired = received.header.recursion_desired;
                response.header.rescode = match received.header.opcode {
                    0 => ResponseCode::NOERROR,
                    _ => ResponseCode::NOTIMP, // Not implemented
                };
                let domain_name = domain_name::DomainName::from("codecrafters.io.");
                let dns_question = DnsQuestion::new(
                    domain_name,
                    question::QueryType::A,
                    question::QueryClass::IN,
                );
                response.questions.push(dns_question);

                response.header.answer_entries = 1;
                let domain_name = domain_name::DomainName::from("codecrafters.io.");
                let dns_answer = DnsRecord::new(
                    domain_name,
                    record::RecordType::A,
                    record::RecordClass::IN,
                    60,
                    std::net::Ipv4Addr::new(8, 8, 8, 8),
                );
                response.answers.push(dns_answer);
                println!("Sent DNS packet: {:#?}", response);

                let bytes_packet = BytesPacket::from(response);

                udp_socket
                    .send_to(&bytes_packet.buf, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }

    Ok(())
}
