use mini_dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start listening on UDP port 67
    println!("Starting DHCP listener on port 67...");
    mini_dhcp::listen().await?;

    Ok(())
}
