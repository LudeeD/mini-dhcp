use crate::{db, Client, MiniDHCPConfiguration};
use futures::future::join_all;

pub async fn get_status(conf: &MiniDHCPConfiguration) -> Vec<Client> {
    let leases = match db::get_all_leases(&conf.leases).await {
        Ok(leases) => leases,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            Vec::new()
        }
    };

    let futures = leases.iter().map(|lease| {
        let ip = std::net::Ipv4Addr::from(lease.ip as u32);
        async move {
            let is_online = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::TcpStream::connect(format!("{}:80", ip)),
            )
            .await
            .is_ok();
            (ip, lease.client_id.clone(), is_online)
        }
    });

    let results = join_all(futures).await;

    let clients = results
        .into_iter()
        .map(|(ip, client_id, is_online)| Client {
            ip,
            client_id: hex::encode(client_id),
            hostname: String::from("todo"),
            online: is_online,
        })
        .collect();

    clients
}
