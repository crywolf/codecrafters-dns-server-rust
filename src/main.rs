use anyhow::Result;
use std::net::UdpSocket;

use crate::{
    header::ResponseCode,
    packet::{BytesPacket, DnsPacket},
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
                response.questions = received.questions;
                response.header.question_entries = response.questions.len() as u16;

                for question in response.questions.iter() {
                    let domain_name = question.domain_name.clone();
                    let dns_answer = DnsRecord::new(
                        domain_name,
                        record::RecordType::A,
                        record::RecordClass::IN,
                        60,
                        std::net::Ipv4Addr::new(8, 8, 8, 8),
                    );
                    response.answers.push(dns_answer);
                }

                response.header.answer_entries = response.answers.len() as u16;

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
