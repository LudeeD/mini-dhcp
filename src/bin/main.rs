use mini_dhcp::{self, MiniDHCPConfiguration};

#[tokio::main]
async fn main() {
    // Start listening on UDP port 67
    tracing_subscriber::fmt::init();

    let conf = MiniDHCPConfiguration::new(String::from("enp0s31f6"))
        .await
        .expect("Expected to be able to build configuration");

    tokio::spawn(mini_dhcp::start(conf.clone()));

    let mut every_second = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        every_second.tick().await;
    }
}
