use crate::{Client, MiniDHCPConfiguration};
use tracing::error;

pub async fn get_status(conf: &MiniDHCPConfiguration) -> Vec<Client> {
    let leases = match conf.leases.get_valid_leases().await {
        Ok(leases) => leases,
        Err(e) => {
            error!("Error: {:?}", e);
            Vec::new()
        }
    };

    leases
        .into_iter()
        .map(|lease| Client {
            ip: lease.ip,
            client_id: hex::encode(lease.client_id),
        })
        .collect()
}
