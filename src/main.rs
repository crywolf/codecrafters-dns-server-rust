use anyhow::Result;
use rand::prelude::*;
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

    // ARGS: --resolver <address>
    let mut resolver_address = String::new();
    let mut args = std::env::args();

    while let Some(arg) = args.next() {
        resolver_address = match arg.as_str() {
            "--resolver" => args.next().expect("missing resolver address"),
            _ => resolver_address,
        };
    }

    loop {
        let mut resolved_answers: Vec<DnsRecord> = Vec::new(); // answers returned by extrenal resolver

        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("< Received {} bytes from {}", size, source);

                let mut bp = BytesPacket::new();
                bp.buf.extend_from_slice(&buf);
                let orig = DnsPacket::from(bp);
                println!("<<< Received DNS packet: {:#?}", orig);

                // Forward to the resolver?
                if !resolver_address.is_empty() {
                    let resolver =
                        UdpSocket::bind("localhost:0").expect("Failed to bind to resolver address");

                    println!(">>> Forwarding to {}", resolver_address);
                    let orig_questions = orig.questions.clone();

                    // Resolver can work only with a single question, we need to split them into separate DNS packets,
                    // send them separately and then merge responses into one DNS packet
                    for q in orig_questions {
                        let mut forwarded = DnsPacket::new();
                        forwarded.header = orig.header;
                        forwarded.questions.push(q);
                        forwarded.header.question_entries = 1;

                        let forwarded_msg_id = random();
                        forwarded.header.id = forwarded_msg_id;
                        println!(">>> Forwarding > Sent DNS packet: {:#?} ", forwarded);

                        let bytes_packet = BytesPacket::from(forwarded);

                        resolver
                            .send_to(&bytes_packet.buf, &resolver_address)
                            .expect("Failed to forward message");

                        let mut buf = [0; 512];
                        resolver
                            .recv_from(&mut buf)
                            .expect("Failed to receive response to forwarded message");

                        let mut bp = BytesPacket::new();
                        bp.buf.extend_from_slice(&buf);

                        let received = DnsPacket::from(bp);

                        println!("<<< Forwarding < Received DNS packet: {:#?}", received);

                        if received.header.id != forwarded_msg_id {
                            anyhow::bail!(
                                "Forwarding: ID mismatch: expected ID {}, got {}",
                                forwarded_msg_id,
                                received.header.id,
                            );
                        }

                        for answer in received.answers {
                            resolved_answers.push(answer);
                        }
                    }
                }

                // Response
                let mut response = DnsPacket::new();
                response.header.id = orig.header.id;
                response.header.response = true;
                response.header.opcode = orig.header.opcode;
                response.header.recursion_desired = orig.header.recursion_desired;
                response.header.rescode = match orig.header.opcode {
                    0 => ResponseCode::NOERROR,
                    _ => ResponseCode::NOTIMP, // Not implemented
                };
                response.questions = orig.questions;
                response.header.question_entries = response.questions.len() as u16;

                if resolved_answers.is_empty() {
                    // manually creating answers
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
                } else {
                    response.answers = resolved_answers; // answers returned by extrenal resolver
                }

                response.header.answer_entries = response.answers.len() as u16;

                println!(">>> Sent DNS packet: {:#?}", response);

                let bytes_packet = BytesPacket::from(response);

                println!("> Sent {} bytes to {}", bytes_packet.buf.len(), source);

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
