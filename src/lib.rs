use anyhow::Context;
use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Message, MessageType, Opcode, OptionCode,
};
use jiff::{ToSpan, Unit, Zoned};
use rand::Rng;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tokio::net::UdpSocket;
mod db;
pub mod info;

#[derive(Debug)]
struct Lease {
    ip: i64,
    client_id: Vec<u8>,
    leased: bool,
    expires_at: i64,
    network: i64,
    probation: bool,
}

#[derive(Debug, Serialize)]
pub struct Client {
    pub ip: Ipv4Addr,
    pub client_id: String,
    pub hostname: String,
    pub online: bool,
}

async fn insert_lease(pool: &SqlitePool, ip: Ipv4Addr, client_id: &Vec<u8>) -> anyhow::Result<()> {
    let ip = u32::from(ip);

    let expire_at = Zoned::now()
        .round(Unit::Second)?
        .checked_add(1.hour())
        .with_context(|| format!("Fuck"))?
        .timestamp()
        .as_second();

    sqlx::query_file!(
        "./db/queries/insert-new-lease.sql",
        ip,
        client_id,
        expire_at,
        0
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn build_dhcp_offer_packet(
    leases: &SqlitePool,
    discover_message: Message,
) -> anyhow::Result<Message> {
    let client_id = discover_message.chaddr().to_vec();

    // The client's current address as recorded in the client's current
    // binding
    // The client's current address as recorded in the client's current
    // binding, ELSE
    //
    // The client's previous address as recorded in the client's (now
    // expired or released) binding, if that address is in the server's
    // pool of available addresses and not already allocated, ELSE
    let mut suggested_address = match db::get_ip_from_client_id(leases, &client_id).await {
        Ok(address) => {
            println!("Client already has IP assigned: {:?}", address);
            Some(address)
        }
        _ => None,
    };

    // The address requested in the 'Requested IP Address' option, if that
    // address is valid and not already allocated, ELSE
    if suggested_address.is_none() {
        let requested_ip_address = discover_message.opts().get(OptionCode::RequestedIpAddress);
        println!("Client requested IP address: {:?}", requested_ip_address);
        match requested_ip_address {
            Some(DhcpOption::RequestedIpAddress(ip)) => {
                if !db::is_ip_assigned(leases, *ip).await? {
                    suggested_address = Some(*ip);
                }
            }
            _ => {
                println!("No requested IP address")
            }
        };
    }

    if suggested_address.is_none() {
        let mut max_tries: u8 = 10;
        loop {
            let random_address = Ipv4Addr::new(192, 168, 1, rand::thread_rng().gen_range(100..200));

            if !db::is_ip_assigned(leases, random_address).await? {
                suggested_address = Some(random_address);
                // insert the lease into the database
                insert_lease(leases, random_address, &client_id).await?;
                break;
            }

            if max_tries == 0 {
                return Err(anyhow::anyhow!("Could not assign IP address"));
            } else {
                max_tries = max_tries.saturating_sub(1);
            }
        }
    }

    let suggested_address = match suggested_address {
        Some(address) => address,
        None => return Err(anyhow::anyhow!("Could not assign IP address")),
    };

    println!("Creating offer");

    let mut offer = Message::default();

    let reply_opcode = Opcode::BootReply;
    offer.set_opcode(reply_opcode);
    offer.set_xid(discover_message.xid());
    offer.set_yiaddr(suggested_address);
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
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(255, 255, 255, 255)));
    offer
        .opts_mut()
        .insert(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 69)]));

    println!("Offer: {:?}", offer);
    Ok(offer)
}

async fn build_dhcp_ack_packet(leases: &SqlitePool, request_message: Message) -> Option<Message> {
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

    let lease = db::get_lease_by_ip(leases, *requested_ip_address)
        .await
        .ok()?;

    if lease.client_id != chaddr {
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
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(255, 255, 255, 255)));
    ack.opts_mut()
        .insert(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 69)]));

    Some(ack)
}

#[derive(Clone)]
pub struct MiniDHCPConfiguration {
    leases: SqlitePool,
}

impl MiniDHCPConfiguration {
    pub async fn new() -> anyhow::Result<Self> {
        let conn = SqliteConnectOptions::from_str("sqlite://dhcp.db")?.create_if_missing(true);

        let leases = SqlitePool::connect_with(conn).await?;

        sqlx::migrate!("./db/migrations").run(&leases).await?;

        Ok(Self { leases })
    }
}

pub async fn start(config: MiniDHCPConfiguration) -> anyhow::Result<()> {
    println!("Starting DHCP listener on port 67...");

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
            let offer = build_dhcp_offer_packet(&config.leases, decoded_message);

            match offer.await {
                Ok(offer) => {
                    println!("Sending {:#?}", offer);

                    let mut buf = Vec::new();
                    let mut e = Encoder::new(&mut buf);
                    offer.encode(&mut e)?;

                    socket.send_to(&buf, "255.255.255.255:68").await?;
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }

            continue;
        }

        if options.has_msg_type(MessageType::Request) {
            let server_identifier = options.get(OptionCode::ServerIdentifier);

            match server_identifier {
                Some(DhcpOption::ServerIdentifier(ip)) => {
                    println!(
                        "Request with server identifier {:?} in response to DHCPOFFER ",
                        ip
                    );
                }
                _ => {
                    println!("No server identifier verify or extend existing lease");
                }
            }

            let ack = build_dhcp_ack_packet(&config.leases, decoded_message);

            if let Some(ack) = ack.await {
                println!("Sending {:#?}", ack);

                let mut buf = Vec::new();
                let mut e = Encoder::new(&mut buf);
                ack.encode(&mut e)?;

                socket.send_to(&buf, "255.255.255.255:68").await?;
            }

            continue;
        }
    }
}
