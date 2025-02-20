# mini-dhcp
![Crates.io Version](https://img.shields.io/crates/v/mini-dhcp)

A lightweight DHCP server implementation in Rust that handles basic DHCP operations including IP address assignment and lease management.

## Features

- Basic DHCP server functionality (DISCOVER, OFFER, REQUEST, ACK)
- SQLite-based lease management
- Configurable network interface binding
- Support for basic DHCP options (subnet mask, router, lease time, etc.)
- IPv4 address pool management (192.168.1.100-200 range)

## Prerequisites

- Rust 1.x
- SQLite3
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

## Database

The server uses SQLite to store lease information. The database file is automatically created as `dhcp.db` in the current directory.

## Supported DHCP Messages

- DISCOVER
- OFFER
- REQUEST
- ACK
- DECLINE (logged only)
- RELEASE (logged only)
- INFORM (logged only)
