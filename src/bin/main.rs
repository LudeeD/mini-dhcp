use mini_dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start listening on UDP port 67
    println!("Starting DHCP listener on port 67...");

    let config = mini_dhcp::MiniDHCPConfiguration::new().await?;

    let handler = tokio::spawn(async {
        match mini_dhcp::listen(config).await {
            Ok(_) => println!("DHCP listener task completed"),
            Err(e) => eprintln!("DHCP listener task failed: {}", e),
        }
    });

    handler.await?;

    Ok(())
}
