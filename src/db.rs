use crate::Lease;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;

pub async fn is_ip_assigned(pool: &SqlitePool, ip: Ipv4Addr) -> Result<bool, sqlx::Error> {
    let arg = u32::from(ip);
    match sqlx::query!("SELECT * FROM leases WHERE ip = ? AND leased", arg)
        .fetch_one(pool)
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

pub async fn get_lease_by_ip(pool: &SqlitePool, ip: &Ipv4Addr) -> Result<Lease, sqlx::Error> {
    let arg = u32::from(*ip);
    sqlx::query_as!(
        Lease,
        "SELECT * FROM leases WHERE ip = ? AND leased ORDER BY expires_at DESC LIMIT 1",
        arg
    )
    .fetch_one(pool)
    .await
}

pub async fn get_all_leases(pool: &SqlitePool) -> Result<Vec<Lease>, sqlx::Error> {
    sqlx::query_as!(Lease, "SELECT * FROM leases")
        .fetch_all(pool)
        .await
}

pub async fn get_ip_from_client_id(
    pool: &SqlitePool,
    client_id: &Vec<u8>,
) -> Result<Ipv4Addr, sqlx::Error> {
    sqlx::query!("SELECT ip FROM leases WHERE client_id = ?", client_id)
        .fetch_one(pool)
        .await
        .map(|row| Ipv4Addr::from(row.ip as u32))
}
