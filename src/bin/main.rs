use mini_dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start listening on UDP port 67

    mini_dhcp::start().await?;

    Ok(())
}
