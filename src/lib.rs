use anyhow::{anyhow, Context};
use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Message, MessageType, Opcode, OptionCode,
};
use jiff::{ToSpan, Unit, Zoned};
use rand::Rng;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::Error;
use std::fmt::format;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug)]
struct Lease {
    ip: i64,
    client_id: Option<Vec<u8>>,
    leased: bool,
    expires_at: i64,
    network: i64,
    probation: bool,
}

async fn is_ip_assigned(pool: &SqlitePool, ip: Ipv4Addr) -> Result<bool, sqlx::Error> {
    let arg = u32::from(ip);
    match sqlx::query_file!("./db/queries/select-by-ip.sql", arg)
        .fetch_one(pool)
        .await
    {
        Ok(_) => Ok(true),
        Err(Error::RowNotFound) => Ok(false),
        Err(e) => Err(e),
    }
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

async fn get_lease(pool: &SqlitePool, ip: &Ipv4Addr) -> anyhow::Result<Lease> {
    let arg = u32::from(ip.clone());
    let lease = sqlx::query_file_as!(Lease, "./db/queries/select-by-ip.sql", arg)
        .fetch_one(pool)
        .await
        .with_context(|| anyhow!("Failed to get lease"))?;

    Ok(lease)
}

async fn build_dhcp_offer_packet(
    leases: &SqlitePool,
    discover_message: Message,
) -> Option<Message> {
    let mut random_address;

    let mut max_tries: u8 = 10;

    loop {
        random_address = Ipv4Addr::new(192, 168, 1, rand::thread_rng().gen_range(100..200));

        if !is_ip_assigned(leases, random_address).await.ok()? {
            break;
        }

        if max_tries == 0 {
            return None;
        } else {
            max_tries = max_tries.saturating_sub(1);
        }
    }

    let mut offer = Message::default();

    let chaddr = discover_message.chaddr().to_owned();

    // insert the lease into the database
    insert_lease(leases, random_address, &chaddr).await.ok()?;

    let reply_opcode = Opcode::BootReply;
    offer.set_opcode(reply_opcode);
    offer.set_xid(discover_message.xid());
    offer.set_yiaddr(random_address);
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
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(192, 168, 1, 255)));

    Some(offer)
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

    let lease = get_lease(leases, requested_ip_address).await.ok()?;

    if lease.client_id != Some(chaddr) {
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
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(192, 168, 1, 255)));

    Some(ack)
}

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

pub async fn listen(config: MiniDHCPConfiguration) -> anyhow::Result<()> {
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

            if let Some(offer) = offer.await {
                println!("Sending {:#?}", offer);

                let mut buf = Vec::new();
                let mut e = Encoder::new(&mut buf);
                offer.encode(&mut e)?;

                socket.send_to(&buf, "192.168.1.255:68").await?;
            }

            continue;
        }

        if options.has_msg_type(MessageType::Request) {
            let ack = build_dhcp_ack_packet(&config.leases, decoded_message);

            if let Some(ack) = ack.await {
                println!("Sending {:#?}", ack);

                let mut buf = Vec::new();
                let mut e = Encoder::new(&mut buf);
                ack.encode(&mut e)?;

                socket.send_to(&buf, "192.168.1.255:68").await?;
            }

            continue;
        }
    }
}
