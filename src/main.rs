use anyhow::Result;
use std::net::UdpSocket;

use crate::packet::{BytesPacket, DnsPacket};

mod header;
mod packet;

fn main() -> Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let mut bp = BytesPacket::new();
                bp.buf.extend_from_slice(&buf);
                let dp = DnsPacket::from(bp);
                println!("Received DNS package: {:#?}", dp);

                let mut dns_packet = DnsPacket::new();
                dns_packet.header.id = 1234;
                dns_packet.header.response = true;

                println!("Sent DNS package: {:#?}", dns_packet);

                let bytes_packet = BytesPacket::from(dns_packet);

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
