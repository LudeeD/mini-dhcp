use mini_dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0".to_string());

    // Start listening on UDP port 67
    println!("Starting DHCP listener on port 67...");
    mini_dhcp::listen(&addr).await?;

    Ok(())
}
