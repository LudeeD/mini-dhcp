# mini-dhcp
![Crates.io Version](https://img.shields.io/crates/v/mini-dhcp)

A lightweight DHCP server implementation in Rust that handles basic DHCP operations including IP address assignment and lease management.

## Features

- Basic DHCP server functionality (DISCOVER, OFFER, REQUEST, ACK, NAK)
- CSV-based lease management (human-readable, easy to inspect/edit)
- Configurable network interface binding
- Support for basic DHCP options (subnet mask, router, lease time, etc.)
- IPv4 address pool management (192.168.1.100-200 range)

## Prerequisites

- Rust 1.x
- Root/sudo privileges (required for binding to port 67)

## Usage

Basic usage example:

```rust
use mini_dhcp::MiniDHCPConfiguration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize the DHCP server with network interface
    let config = MiniDHCPConfiguration::new("eth0".to_string()).await?;

    // Start the DHCP server
    mini_dhcp::start(config).await?;

    Ok(())
}
```

## Configuration

The DHCP server is configured to:

- Listen on port 67
- Assign IP addresses in the range 192.168.1.100-200
- Use 192.168.1.69 as the default gateway
- Set lease time to 1 hour (3600 seconds)
- Use 255.255.255.0 as subnet mask

## Lease Storage

The server stores lease information in a CSV file (`leases.csv`) in the current directory. The file is human-readable and can be inspected or edited manually if needed.

## Supported DHCP Messages

- DISCOVER
- OFFER
- REQUEST
- ACK/NAK
- DECLINE
- RELEASE
- INFORM

## RFC 2131 Compliance

This server is designed for **single-server environments** and has known deviations from RFC 2131/2132.

For a complete list of deviations, see [DEVIATIONS.md](DEVIATIONS.md).

**Key intentional deviation:** When a client attempts to renew or rebind a lease that the server has no record of (e.g., after server restart), RFC 2131 specifies the server MUST remain silent. Instead, mini-dhcp accepts the renewal if the IP is available - providing better UX in single-server setups.

If you're running multiple DHCP servers on the same network, this behavior may cause conflicts.
