use mini_dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start listening on UDP port 67

    let config = mini_dhcp::MiniDHCPConfiguration::new().await?;

    let config_dhcp = config.clone();

    let handler_dhcp = tokio::spawn(async {
        match mini_dhcp::start(config_dhcp).await {
            Ok(_) => println!("DHCP listener task completed"),
            Err(e) => eprintln!("DHCP listener task failed: {}", e),
        }
    });

    tokio::spawn(async {
        match mini_dhcp::start_info_server(config).await {
            Ok(_) => println!("Info server task completed"),
            Err(e) => eprintln!("Info server task failed: {}", e),
        }
    });

    handler_dhcp.await?;

    Ok(())
}
