use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Message, MessageType, Opcode, OptionCode,
};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

pub fn build_dhcp_discover_packet(bytes: &[u8]) -> Message {
    let msg = Message::from_bytes(bytes).unwrap();
    println!("{:?}", msg);

    msg
}

/// Builds a DHCP OFFER packet in response to a DHCP DISCOVER
pub fn build_dhcp_offer_packet(
    transaction_id: u32,
    client_mac: [u8; 6],
    server_ip: Ipv4Addr,
) -> Option<Message> {
    let mut offer = Message::default();

    offer.set_xid(transaction_id); // Transaction ID
    offer.set_yiaddr(Ipv4Addr::new(192, 168, 1, 100));
    offer.set_siaddr(Ipv4Addr::new(192, 168, 1, 69));
    offer.set_chaddr(&client_mac); // Client MAC address

    // DHCP Options
    offer
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Offer));
    offer
        .opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_ip));
    offer
        .opts_mut()
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0))); // Example subnet mask
    offer.opts_mut().insert(DhcpOption::Router(vec![server_ip])); // Example gateway option
    offer.opts_mut().insert(DhcpOption::End);

    Some(offer)
}

pub async fn listen() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:67").await?;
    socket.set_broadcast(true)?;

    let mut buf = vec![0u8; 1024];
    loop {
        // Receive a packet
        socket.recv_from(&mut buf).await?;

        let decoded_message = Message::decode(&mut Decoder::new(&buf))?;

        if decoded_message.chaddr()[0] == 160 {
            println!("{:?}", decoded_message);
        }
    }
}
