use anyhow::Context;
use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Message, MessageType, Opcode, OptionCode,
};
use jiff::{ToSpan, Unit, Zoned};
use rand::Rng;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{error, info, warn};
pub mod db;
pub mod info;
pub mod migration;

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

async fn insert_lease(
    store: &db::LeaseStore,
    ip: Ipv4Addr,
    client_id: &Vec<u8>,
) -> anyhow::Result<()> {
    let expire_at = Zoned::now()
        .round(Unit::Second)?
        .checked_add(1.hour())
        .with_context(|| "Failed to calculate lease expiry time".to_string())?
        .timestamp()
        .as_second();

    let lease = db::Lease {
        ip,
        client_id: client_id.clone(),
        leased: true,
        expires_at: expire_at,
        network: 0,
        probation: false,
    };

    store.insert_lease(lease).await?;
    Ok(())
}

async fn build_dhcp_offer_packet(
    leases: &db::LeaseStore,
    discover_message: &Message,
) -> anyhow::Result<Message> {
    let xid = discover_message.xid();
    let client_id = discover_message.chaddr().to_vec();

    // The client's current address as recorded in the client's current
    // binding
    // The client's current address as recorded in the client's current
    // binding, ELSE
    //
    // The client's previous address as recorded in the client's (now
    // expired or released) binding, if that address is in the server's
    // pool of available addresses and not already allocated, ELSE
    let mut suggested_address = match leases.get_ip_from_client_id(&client_id).await {
        Ok(address) => {
            // Check if this lease has expired
            match leases.get_lease_by_ip(&address).await {
                Ok(lease) => {
                    let current_time = Zoned::now().round(Unit::Second)?.timestamp().as_second();
                    if lease.expires_at < current_time {
                        // Lease has expired, renew it
                        let new_expiry = Zoned::now()
                            .round(Unit::Second)?
                            .checked_add(1.hour())
                            .with_context(|| "Failed to calculate lease expiry time".to_string())?
                            .timestamp()
                            .as_second();
                        leases.update_lease_expiry(address, new_expiry).await?;
                        info!(
                            "[{xid:X}] [OFFER] Client {:?} has expired lease for {:?}, renewed",
                            client_id, address
                        );
                    } else {
                        info!(
                            "[{xid:X}] [OFFER] Client {:?} already has IP assigned: {:?}",
                            client_id, address
                        );
                    }
                    Some(address)
                }
                Err(_) => {
                    warn!(
                        "[{xid:X}] [OFFER] Could not fetch lease details for {:?}",
                        address
                    );
                    Some(address)
                }
            }
        }
        _ => {
            warn!(
                "[{xid:X}] [OFFER] Client {:?} has no IP assigned in the database",
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
            "[{xid:X}] [OFFER] Client requested IP address: {:?}",
            requested_ip_address
        );
        match requested_ip_address {
            Some(DhcpOption::RequestedIpAddress(ip)) => {
                if !leases.is_ip_assigned(*ip).await? && check_ip_in_range(*ip) {
                    insert_lease(leases, *ip, &client_id).await?;
                    suggested_address = Some(*ip);
                }
            }
            _ => {
                warn!("[{xid:X}] [OFFER] No requested IP address")
            }
        };
    }

    // A new address allocated from the server's pool of available addresses
    if suggested_address.is_none() {
        for _ in 0..10 {
            let random_address = get_ip_in_range();
            if !leases.is_ip_assigned(random_address).await? {
                insert_lease(leases, random_address, &client_id).await?;
                suggested_address = Some(random_address);
                break;
            }
        }
    }

    let suggested_address = match suggested_address {
        Some(address) => address,
        None => return Err(anyhow::anyhow!("Could not assign IP address")),
    };

    info!(
        "[{xid:X}] [OFFER] Creating offer with IP {}",
        suggested_address
    );

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

/// Response type for DHCP REQUEST handling
#[derive(Debug)]
enum DhcpResponse {
    Ack(Message),
    Nak(Message),
}

/// Build a DHCP NAK packet according to RFC 2131 Table 3
fn build_dhcp_nack_packet(request_message: &Message, reason: &str) -> Message {
    let xid = request_message.xid();
    info!("[{xid:X}] [NAK] Sending: {}", reason);

    let mut nak = Message::default();
    nak.set_opcode(Opcode::BootReply);
    nak.set_xid(request_message.xid());
    nak.set_flags(request_message.flags());
    nak.set_chaddr(request_message.chaddr());

    // RFC 2131 Table 3: yiaddr and siaddr must be 0 for NACK
    nak.set_yiaddr(Ipv4Addr::new(0, 0, 0, 0));
    nak.set_siaddr(Ipv4Addr::new(0, 0, 0, 0));

    // Only include MessageType and ServerIdentifier options
    nak.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Nak));
    nak.opts_mut()
        .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 69)));

    nak
}

async fn build_dhcp_ack_packet(
    leases: &db::LeaseStore,
    request_message: &Message,
) -> anyhow::Result<DhcpResponse> {
    let xid = request_message.xid();
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
                info!("[{xid:X}] [ACK] Client requested IP address: {:?}", ip);
                ip
            }
            _ => {
                return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                    request_message,
                    "Client didn't provide requested IP address",
                )));
            }
        }
    } else if is_renewing_rebinding {
        info!("[{xid:X}] [ACK] Using ciaddr {:?}", ciaddr);
        &ciaddr
    } else {
        return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
            request_message,
            "DHCPREQUEST does not match any known valid state",
        )));
    };

    // 4) Validate that the IP is on the correct subnet (RFC says to NAK if it's on the wrong net).
    //    Also check if you have a valid lease for this client in your DB, etc.

    // First check if IP is in valid range
    if !check_ip_in_range(*ip_to_validate) {
        return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
            request_message,
            "Requested IP address is outside valid range",
        )));
    }

    let lease = match leases.get_lease_by_ip(ip_to_validate).await {
        Ok(lease) => Some(lease),
        Err(db::LeaseError::NotFound) => {
            // No lease exists - check if IP is already assigned to someone else
            if leases.is_ip_assigned(*ip_to_validate).await? {
                warn!(
                    "[{xid:X}] [ACK] IP {:?} is assigned to another client",
                    ip_to_validate
                );
                return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                    request_message,
                    "IP address is assigned to another client",
                )));
            }

            // Lenient mode: accept the client's claimed IP if it's in range and available.
            // This deviates from RFC 2131 which says to remain silent when we have no record,
            // but provides better UX for single-server setups (e.g., after server restart).
            info!(
                "[{xid:X}] [ACK] No lease record found, creating lease for {:?}",
                ip_to_validate
            );
            insert_lease(leases, *ip_to_validate, &chaddr).await?;
            None
        }
        Err(e) => {
            warn!("[{xid:X}] [ACK] Database error: {:?}", e);
            return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                request_message,
                "Database error",
            )));
        }
    };

    // Validate the lease if it exists (skip if we just created it)
    if let Some(lease) = &lease {
        if !lease.leased {
            return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                request_message,
                "IP address is not currently leased",
            )));
        }

        // Check if lease has expired
        let current_time = Zoned::now().round(Unit::Second)?.timestamp().as_second();
        if lease.expires_at < current_time {
            warn!(
                "[{xid:X}] [ACK] Lease has expired: expires_at={}, current={}",
                lease.expires_at, current_time
            );
            return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                request_message,
                "Lease has expired",
            )));
        }

        // Validate that the client_id matches the lease
        if lease.client_id != chaddr {
            warn!(
                "[{xid:X}] [ACK] Client ID mismatch: lease has {:?}, request has {:?}",
                lease.client_id, chaddr
            );
            return Ok(DhcpResponse::Nak(build_dhcp_nack_packet(
                request_message,
                "IP address is leased to a different client",
            )));
        }
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

    // Update lease expiry time in database
    let new_expiry = Zoned::now()
        .round(Unit::Second)?
        .checked_add(1.hour())
        .with_context(|| "Failed to calculate new lease expiry time".to_string())?
        .timestamp()
        .as_second();

    leases
        .update_lease_expiry(*ip_to_validate, new_expiry)
        .await?;

    Ok(DhcpResponse::Ack(ack))
}

#[derive(Clone)]
pub struct MiniDHCPConfiguration {
    interface: String,
    event_queue: Vec<mpsc::Sender<String>>,
    pub leases: db::LeaseStore,
}

pub struct MiniDHCPConfigurationBuilder {
    interface: Option<String>,
    event_queue: Vec<mpsc::Sender<String>>,
}

impl MiniDHCPConfigurationBuilder {
    pub fn new() -> MiniDHCPConfigurationBuilder {
        Self {
            interface: None,
            event_queue: Vec::new(),
        }
    }

    pub fn set_listening_interface(mut self, interface: &str) -> Self {
        self.interface = Some(interface.into());
        self
    }

    pub fn set_event_queue(mut self, event_queue: mpsc::Sender<String>) -> Self {
        self.event_queue.push(event_queue);
        self
    }

    pub async fn build(self) -> anyhow::Result<MiniDHCPConfiguration> {
        let interface = self
            .interface
            .ok_or_else(|| anyhow::anyhow!("Interface not set"))?;

        let leases = db::LeaseStore::new(PathBuf::from("leases.csv")).await?;

        let event_queue = self.event_queue;

        Ok(MiniDHCPConfiguration {
            interface,
            leases,
            event_queue,
        })
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

    let response = build_dhcp_ack_packet(&config.leases, decoded_message).await?;

    match response {
        DhcpResponse::Ack(ack) => {
            let offered_ip = ack.yiaddr();
            info!(
                "[{:X}] [ACK]: {:?} {:?}",
                transaction_id, client_address, offered_ip
            );

            // Send notification to event queue
            for sender in &config.event_queue {
                let msg = format!("NEW_LEASE: {} -> {:?}", offered_ip, client_address);
                let _ = sender.try_send(msg);
            }

            let mut buf = Vec::new();
            let mut e = Encoder::new(&mut buf);
            ack.encode(&mut e)?;
            Ok(buf)
        }
        DhcpResponse::Nak(nak) => {
            info!("[{:X}] [NAK]: {:?}", transaction_id, client_address);

            let mut buf = Vec::new();
            let mut e = Encoder::new(&mut buf);
            nak.encode(&mut e)?;
            Ok(buf)
        }
    }
}

pub async fn start(config: MiniDHCPConfiguration) -> anyhow::Result<()> {
    let address = "0.0.0.0:67";
    info!("Starting DHCP listener [{}] {}", config.interface, address);
    let socket = UdpSocket::bind(address).await?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some(config.interface.as_bytes()))?;

    loop {
        // Receive a packet
        let mut read_buffer = vec![0u8; 1024];
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
                if let Err(e) = socket.send_to(&response, "255.255.255.255:68").await {
                    error!(
                        "[{:X}] [OFFER] Failed to send in socket: {:?}",
                        transaction_id, e
                    );
                }
            } else {
                error!("[ERROR] handling DISCOVER {:?}", response);
            }
            continue;
        }

        if options.has_msg_type(MessageType::Request) {
            let transaction_id = decoded_message.xid();
            let response = handle_request(&config, &decoded_message).await;
            if let Ok(response) = response {
                info!("[{:X}] [ACK/NAK] Sending...", transaction_id);
                if let Err(e) = socket.send_to(&response, "255.255.255.255:68").await {
                    error!(
                        "[{:X}] [ACK/NAK] Failed to send in socket: {:?}",
                        transaction_id, e
                    );
                }
            } else {
                error!("[ERROR] handling REQUEST {:?}", response);
            }
            continue;
        }

        if options.has_msg_type(MessageType::Decline) {
            let transaction_id = decoded_message.xid();
            let requested_ip = decoded_message.opts().get(OptionCode::RequestedIpAddress);

            if let Some(DhcpOption::RequestedIpAddress(ip)) = requested_ip {
                info!(
                    "[{:X}] [DECLINE] Client declined IP {:?} (address conflict detected)",
                    transaction_id, ip
                );
                if let Err(e) = config.leases.mark_ip_declined(*ip).await {
                    error!(
                        "[{:X}] [DECLINE] Failed to mark IP as declined: {:?}",
                        transaction_id, e
                    );
                } else {
                    info!(
                        "[{:X}] [DECLINE] IP {:?} marked as unavailable",
                        transaction_id, ip
                    );
                }
            } else {
                warn!(
                    "[{:X}] [DECLINE] No requested IP in DECLINE message",
                    transaction_id
                );
            }
            continue;
        }

        if options.has_msg_type(MessageType::Release) {
            let transaction_id = decoded_message.xid();
            let client_id = decoded_message.chaddr().to_vec();
            let ciaddr = decoded_message.ciaddr();

            info!(
                "[{:X}] [RELEASE] Client releasing IP {:?}",
                transaction_id, ciaddr
            );
            if let Err(e) = config.leases.release_lease(ciaddr, &client_id).await {
                error!(
                    "[{:X}] [RELEASE] Failed to release lease: {:?}",
                    transaction_id, e
                );
            } else {
                info!(
                    "[{:X}] [RELEASE] Lease for {:?} released",
                    transaction_id, ciaddr
                );
            }
            continue;
        }
        if options.has_msg_type(MessageType::Inform) {
            let transaction_id = decoded_message.xid();
            info!("[{:X}] [INFORM]", transaction_id);
            continue;
        }
    }
}
