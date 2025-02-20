use crate::{db, Client, MiniDHCPConfiguration};
use tracing::error;

pub async fn get_status(conf: &MiniDHCPConfiguration) -> Vec<Client> {
    let leases = match db::get_all_leases(&conf.leases).await {
        Ok(leases) => leases,
        Err(e) => {
            error!("Error: {:?}", e);
            Vec::new()
        }
    };

    leases
        .into_iter()
        .map(|lease| Client {
            ip: std::net::Ipv4Addr::from(lease.ip as u32),
            client_id: hex::encode(lease.client_id),
        })
        .collect()
}
