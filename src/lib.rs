use dhcproto::v4::{Decodable, Decoder, Encodable, Encoder, Message, Opcode};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

pub fn build_dhcp_discover_packet(bytes: &[u8]) -> Message {
    let msg = Message::from_bytes(bytes).unwrap();
    println!("{:?}", msg);

    msg
}

pub async fn listen(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(addr).await?;

    let mut buf = vec![0u8; 1024];

    loop {
        // Receive a packet
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("Received packet from: {}", addr);

        let decoded_message = Message::decode(&mut Decoder::new(&buf))?;

        println!("{:?}", decoded_message);
    }
}
