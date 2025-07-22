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
use tracing::{error, info, warn};
mod db;
pub mod info;

#[allow(dead_code)]
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
}

fn check_ip_in_range(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    a == 192 && b == 168 && c == 1 && (100..200).contains(&d)
}

fn get_ip_in_range() -> Ipv4Addr {
    let octet = rand::thread_rng().gen_range(100..200);
    Ipv4Addr::new(192, 168, 1, octet)
}

async fn insert_lease(pool: &SqlitePool, ip: Ipv4Addr, client_id: &Vec<u8>) -> anyhow::Result<()> {
    let ip = u32::from(ip);

    let expire_at = Zoned::now()
        .round(Unit::Second)?
        .checked_add(1.hour())
        .with_context(|| "Fuck".to_string())?
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
    discover_message: &Message,
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
            info!(
                "[OFFER] Client {:?} already has IP assigned: {:?}",
                client_id, address
            );
            Some(address)
        }
        _ => {
            warn!(
                "[OFFER] Client {:?} has no IP assigned in the database",
                client_id
            );
            None
        }
    };

    // The address requested in the 'Requested IP Address' option, if that
    // address is valid and not already allocated, ELSE
    if suggested_address.is_none() {
        let requested_ip_address = discover_message.opts().get(OptionCode::RequestedIpAddress);
        info!(
            "[OFFER] Client requested IP address: {:?}",
            requested_ip_address
        );
        match requested_ip_address {
            Some(DhcpOption::RequestedIpAddress(ip)) => {
                if !db::is_ip_assigned(leases, *ip).await? && check_ip_in_range(*ip) {
                    suggested_address = Some(*ip);
                }
            }
            _ => {
                warn!("[OFFER] No requested IP address")
            }
        };
    }

    if suggested_address.is_none() {
        let mut max_tries: u8 = 10;
        loop {
            let random_address = get_ip_in_range();

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

    info!("[OFFER] creating offer with IP {}", suggested_address);

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

    Ok(offer)
}

async fn build_dhcp_ack_packet(
    leases: &SqlitePool,
    request_message: &Message,
) -> anyhow::Result<Message> {
    let server_identifier_option = request_message.opts().get(OptionCode::ServerIdentifier);

    let requested_ip_option = request_message.opts().get(OptionCode::RequestedIpAddress);

    // `ciaddr` is the client’s current IP address (used in RENEWING/REBINDING)
    let ciaddr = request_message.ciaddr();
    let chaddr = request_message.chaddr().to_owned();

    let (is_selecting, is_init_reboot, is_renewing_rebinding) = {
        let have_server_id = server_identifier_option.is_some();
        let have_requested_ip = requested_ip_option.is_some();
        let ciaddr_is_zero = ciaddr == Ipv4Addr::new(0, 0, 0, 0);

        // SELECTING state
        let selecting = have_server_id && have_requested_ip && ciaddr_is_zero;

        // INIT-REBOOT
        let init_reboot = !have_server_id && have_requested_ip && ciaddr_is_zero;

        // RENEWING/REBINDING: ciaddr != 0, no 'requested IP address'
        let renewing_rebinding = ciaddr != Ipv4Addr::new(0, 0, 0, 0) && !have_requested_ip;

        (selecting, init_reboot, renewing_rebinding)
    };

    let ip_to_validate = if is_selecting || is_init_reboot {
        match requested_ip_option {
            Some(DhcpOption::RequestedIpAddress(ip)) => {
                info!("[ACK] Client requested IP address: {:?}", ip);
                ip
            }
            _ => {
                anyhow::bail!("[ACK] Client didnt requested IP address")
            }
        }
    } else if is_renewing_rebinding {
        info!("[ACK] using ciaddr {:?}", ciaddr);
        &ciaddr
    } else {
        anyhow::bail!("[ACK] DHCPREQUEST does not match any known valid state.");
    };

    // 4) Validate that the IP is on the correct subnet (RFC says to NAK if it’s on the wrong net).
    //    Also check if you have a valid lease for this client in your DB, etc.
    let lease = match db::get_lease_by_ip(leases, ip_to_validate).await {
        Ok(lease) => lease,
        Err(e) => {
            anyhow::bail!("[ACK] NO RECORD FOUND ON DB {:?}", e);
        }
    };

    if !lease.leased {
        anyhow::bail!("[ACK] IP address is not leased");
    }

    let mut ack = Message::default();
    ack.set_opcode(Opcode::BootReply);
    ack.set_xid(request_message.xid());
    ack.set_flags(request_message.flags());
    ack.set_giaddr(request_message.giaddr());
    ack.set_chaddr(&chaddr);

    ack.set_yiaddr(*ip_to_validate);

    ack.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Ack));
    ack.opts_mut()
        .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 69)));

    ack.opts_mut().insert(DhcpOption::AddressLeaseTime(3600));
    ack.opts_mut()
        .insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    ack.opts_mut()
        .insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(255, 255, 255, 255)));
    ack.opts_mut()
        .insert(DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 69)]));

    Ok(ack)
}

#[derive(Clone)]
pub struct MiniDHCPConfiguration {
    interface: String,
    leases: SqlitePool,
}

impl MiniDHCPConfiguration {
    pub async fn new(interface: String) -> anyhow::Result<Self> {
        let conn = SqliteConnectOptions::from_str("sqlite://dhcp.db")?.create_if_missing(true);

        let leases = SqlitePool::connect_with(conn).await?;

        sqlx::migrate!("./db/migrations").run(&leases).await?;

        Ok(Self { leases, interface })
    }
}

async fn handle_discover(
    config: &MiniDHCPConfiguration,
    decoded_message: &Message,
) -> anyhow::Result<Vec<u8>> {
    let transaction_id = decoded_message.xid();
    let client_address = decoded_message.chaddr();
    info!("[{:X}] DISCOVER {:?}", transaction_id, client_address);
    let offer = build_dhcp_offer_packet(&config.leases, decoded_message);

    match offer.await {
        Ok(offer) => {
            let offered_ip = offer.yiaddr();
            info!(
                "[{:X}] [OFFER]: client {:?} ip {:?}",
                transaction_id, client_address, offered_ip
            );

            let mut buf = Vec::new();
            let mut e = Encoder::new(&mut buf);
            offer.encode(&mut e)?;
            Ok(buf)
        }
        Err(e) => {
            anyhow::bail!("OFFER Error: {:?}", e)
        }
    }
}

async fn handle_request(
    config: &MiniDHCPConfiguration,
    decoded_message: &Message,
) -> anyhow::Result<Vec<u8>> {
    let options = decoded_message.opts();
    let transaction_id = decoded_message.xid();
    let client_address = decoded_message.chaddr();
    let server_identifier = options.get(OptionCode::ServerIdentifier);
    info!(
        "[{:X}] REQUEST from {:?} to {:?}",
        transaction_id, client_address, server_identifier
    );

    let ack = build_dhcp_ack_packet(&config.leases, decoded_message);

    match ack.await {
        Ok(ack) => {
            let mut buf = Vec::new();
            let mut e = Encoder::new(&mut buf);
            ack.encode(&mut e)?;
            let offered_ip = ack.yiaddr();
            info!(
                "[{:X}] [ACK]: {:?} {:?}",
                transaction_id, client_address, offered_ip
            );
            Ok(buf)
        }
        Err(e) => {
            anyhow::bail!("ACK Error: {:?}", e)
        }
    }
}

pub async fn start(config: MiniDHCPConfiguration) -> anyhow::Result<()> {
    let address = "0.0.0.0:67";
    info!("Starting DHCP listener [{}] {}", config.interface, address);
    let socket = UdpSocket::bind(address).await?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some(config.interface.as_bytes()))?;

    let mut read_buffer = vec![0u8; 1024];

    loop {
        // Receive a packet
        let (_len, addr) = socket.recv_from(&mut read_buffer).await?;
        info!("== Received packet from {:?} ==", addr);

        let decoded_message = Message::decode(&mut Decoder::new(&read_buffer))?;
        // https://datatracker.ietf.org/doc/html/rfc2131#page-13
        // The 'op' field of each DHCP message sent from a client to a server contains BOOTREQUEST.
        if decoded_message.opcode() != Opcode::BootRequest {
            error!("[ERROR] opcode is not BootRequest, ignoring message");
            continue;
        }

        let options = decoded_message.opts();

        if options.has_msg_type(MessageType::Discover) {
            let transaction_id = decoded_message.xid();
            let response = handle_discover(&config, &decoded_message).await;
            if let Ok(response) = response {
                info!("[{:X}] [OFFER] Sending...", transaction_id);
                socket
                    .send_to(&response, "255.255.255.255:68")
                    .await
                    .expect("[OFFER] Failed to send in socket");
            } else {
                error!("[ERROR] handling DISCOVER {:?}", response);
            }
            continue;
        }

        if options.has_msg_type(MessageType::Request) {
            let transaction_id = decoded_message.xid();
            let response = handle_request(&config, &decoded_message).await;
            if let Ok(response) = response {
                info!("[{:X}] [ACK] Sending...", transaction_id);
                socket
                    .send_to(&response, "255.255.255.255:68")
                    .await
                    .expect("[ACK] Failed to send in socket");
            } else {
                error!("[ERROR] handling REQUEST {:?}", response);
            }
            continue;
        }

        if options.has_msg_type(MessageType::Decline) {
            let transaction_id = decoded_message.xid();
            info!("[{:X}] [DECLINE]", transaction_id);
            continue;
        }

        if options.has_msg_type(MessageType::Release) {
            let transaction_id = decoded_message.xid();
            info!("[{:X}] [RELEASE]", transaction_id);
            continue;
        }
        if options.has_msg_type(MessageType::Inform) {
            let transaction_id = decoded_message.xid();
            info!("[{:X}] [INFORM]", transaction_id);
            continue;
        }
    }
}
