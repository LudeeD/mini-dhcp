use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Message, MessageType, Opcode, OptionCode,
};
use std::{collections::HashMap, net::Ipv4Addr};
use tokio::net::UdpSocket;

/// Builds a DHCP OFFER packet in response to a DHCP DISCOVER
fn build_dhcp_offer_packet(
    yiaddr: Ipv4Addr,
    leases: &mut HashMap<Ipv4Addr, Vec<u8>>,
    discover_message: Message,
) -> Option<Message> {
    let mut offer = Message::default();

    let chaddr = discover_message.chaddr().to_owned();

    leases.insert(yiaddr, chaddr);

    let reply_opcode = Opcode::BootReply;
    offer.set_opcode(reply_opcode);
    offer.set_xid(discover_message.xid()); // Transaction ID
    offer.set_yiaddr(yiaddr);
    offer.set_siaddr(Ipv4Addr::new(192, 168, 1, 69));
    offer.set_flags(discover_message.flags());
    offer.set_giaddr(discover_message.giaddr());
    offer.set_chaddr(discover_message.chaddr());

    offer
        .opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Offer));
    offer.opts_mut().insert(DhcpOption::AddressLeaseTime(3600));
    offer
        .opts_mut()
        .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 69)));
    offer
        .opts_mut()
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    offer
        .opts_mut()
        .insert(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]));
    offer
        .opts_mut()
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(192, 168, 1, 255)));

    Some(offer)
}

fn build_dhcp_ack_packet(
    leases: &mut HashMap<Ipv4Addr, Vec<u8>>,
    request_message: Message,
) -> Option<Message> {
    // checks
    let server_identifier = request_message.opts().get(OptionCode::ServerIdentifier);
    println!("Server identifier: {:?}", server_identifier);

    let ciadr = request_message.ciaddr();
    println!("Client address: {:?}", ciadr);

    let requested_ip_address = request_message.opts().get(OptionCode::RequestedIpAddress);
    println!("Requested IP address: {:?}", requested_ip_address);
    let requested_ip_address = match requested_ip_address {
        Some(DhcpOption::RequestedIpAddress(ip)) => ip,
        _ => return None,
    };

    let mut ack = Message::default();

    let chaddr = request_message.chaddr().to_owned();

    // check if the client has a lease
    let expected_chaddr = leases.get(requested_ip_address).unwrap();
    if expected_chaddr != &chaddr {
        println!("Client does not have a lease");
        return None;
    }

    ack.set_opcode(Opcode::BootReply);
    ack.set_xid(request_message.xid()); // Transaction ID
    ack.set_yiaddr(requested_ip_address.clone());
    ack.set_siaddr(Ipv4Addr::new(192, 168, 1, 69));
    ack.set_flags(request_message.flags());
    ack.set_giaddr(request_message.giaddr());
    ack.set_chaddr(request_message.chaddr());

    ack.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Ack));
    ack.opts_mut().insert(DhcpOption::AddressLeaseTime(3600));
    ack.opts_mut()
        .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 69)));
    ack.opts_mut()
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    ack.opts_mut()
        .insert(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]));
    ack.opts_mut()
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(192, 168, 1, 255)));

    Some(ack)
}

pub async fn listen() -> Result<(), Box<dyn std::error::Error>> {
    let mut leases = HashMap::new();
    let mut available = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)];

    let socket = UdpSocket::bind("0.0.0.0:67").await?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some("enP8p1s0".as_bytes()))?;

    let mut buf = vec![0u8; 1024];
    loop {
        // Receive a packet
        let (_len, addr) = socket.recv_from(&mut buf).await?;

        let decoded_message = Message::decode(&mut Decoder::new(&buf))?;

        let options = decoded_message.opts();

        if options.has_msg_type(MessageType::Discover) {
            let yiaddr = available.pop().unwrap();

            let offer = build_dhcp_offer_packet(yiaddr, &mut leases, decoded_message);

            if let Some(offer) = offer {
                println!("Sending {:#?}", offer);

                let mut buf = Vec::new();
                let mut e = Encoder::new(&mut buf);
                offer.encode(&mut e)?;

                socket.send_to(&buf, "192.168.1.255:68").await?;
            }

            continue;
        }

        if options.has_msg_type(MessageType::Request) {
            let ack = build_dhcp_ack_packet(&mut leases, decoded_message);

            if let Some(ack) = ack {
                println!("Sending {:#?}", ack);

                let mut buf = Vec::new();
                let mut e = Encoder::new(&mut buf);
                ack.encode(&mut e)?;

                socket.send_to(&buf, "192.168.1.255:68").await?;
            }
        }
    }
}
