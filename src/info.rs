use crate::{db, Client, MiniDHCPConfiguration};
use axum::{extract::State, routing::get, Json, Router};
use futures::future::join_all;

pub async fn start_info_server(config: MiniDHCPConfiguration) -> anyhow::Result<()> {
    println!("Starting DHCP info server listener on port 6767...");
    let app = Router::new()
        .route("/leases", get(get_leases_handler))
        .with_state(config);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("localhost:6767")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn get_leases_handler(State(state): State<MiniDHCPConfiguration>) -> Json<Vec<Client>> {
    let leases = match db::get_all_leases(&state.leases).await {
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

    Json(clients)
}
