use mini_dhcp::{self, MiniDHCPConfiguration, MiniDHCPConfigurationBuilder};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    // Start listening on UDP port 67
    tracing_subscriber::fmt::init();

    let (event_sender, mut event_receiver) = mpsc::channel(100);

    let conf: MiniDHCPConfiguration = MiniDHCPConfigurationBuilder::new()
        .set_listening_interface("enp0s31f6")
        .set_event_queue(event_sender)
        .build()
        .await
        .expect("Expected to be able to build configuration");

    tokio::spawn(mini_dhcp::start(conf.clone()));

    loop {
        if let Some(event) = event_receiver.recv().await {
            println!("Received event: {}", event);
        }
    }
}
