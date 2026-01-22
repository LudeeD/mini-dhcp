use crate::migration::{maybe_migrate, MigrationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum LeaseError {
    #[error("Lease not found")]
    NotFound,

    #[error("Client ID mismatch")]
    ClientMismatch,

    #[error("CSV error: {0}")]
    CsvError(#[from] csv::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    #[serde(with = "ipv4_serde")]
    pub ip: Ipv4Addr,
    #[serde(with = "mac_serde")]
    pub client_id: Vec<u8>,
    pub leased: bool,
    pub expires_at: i64,
    pub network: i64,
    pub probation: bool,
}

mod ipv4_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::net::Ipv4Addr;

    pub fn serialize<S>(ip: &Ipv4Addr, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&ip.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv4Addr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

mod mac_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str: String = bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        s.split(':')
            .map(|part| u8::from_str_radix(part, 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[derive(Clone)]
pub struct LeaseStore {
    leases: Arc<RwLock<HashMap<Ipv4Addr, Lease>>>,
    file_path: PathBuf,
}

impl LeaseStore {
    pub async fn new(file_path: PathBuf) -> Result<Self, LeaseError> {
        // Attempt migration from SQLite if needed
        match maybe_migrate(&file_path) {
            MigrationResult::Migrated(count) => {
                info!("Migrated {} leases from SQLite to CSV", count);
            }
            MigrationResult::Skipped => {
                info!("Migration skipped: CSV file already exists");
            }
            MigrationResult::NoDatabase => {
                info!("No SQLite database found, starting fresh");
            }
            MigrationResult::Failed(err) => {
                warn!("Migration failed: {}. Starting with empty lease store.", err);
            }
        }

        let leases = if file_path.exists() {
            Self::load_from_csv(&file_path)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            leases: Arc::new(RwLock::new(leases)),
            file_path,
        })
    }

    fn load_from_csv(path: &PathBuf) -> Result<HashMap<Ipv4Addr, Lease>, LeaseError> {
        let mut reader = csv::Reader::from_path(path)?;
        let mut leases = HashMap::new();
        for result in reader.deserialize() {
            let lease: Lease = result?;
            leases.insert(lease.ip, lease);
        }
        Ok(leases)
    }

    async fn flush(&self) -> Result<(), LeaseError> {
        let leases = self.leases.read().await;
        let mut writer = csv::Writer::from_path(&self.file_path)?;
        for lease in leases.values() {
            writer.serialize(lease)?;
        }
        writer.flush()?;
        Ok(())
    }

    pub async fn insert_lease(&self, lease: Lease) -> Result<(), LeaseError> {
        {
            let mut leases = self.leases.write().await;
            leases.insert(lease.ip, lease);
        }
        self.flush().await
    }

    pub async fn get_lease_by_ip(&self, ip: &Ipv4Addr) -> Result<Lease, LeaseError> {
        let leases = self.leases.read().await;
        leases
            .get(ip)
            .filter(|lease| lease.leased)
            .cloned()
            .ok_or(LeaseError::NotFound)
    }

    pub async fn get_ip_from_client_id(&self, client_id: &Vec<u8>) -> Result<Ipv4Addr, LeaseError> {
        let leases = self.leases.read().await;
        leases
            .values()
            .find(|lease| &lease.client_id == client_id)
            .map(|lease| lease.ip)
            .ok_or(LeaseError::NotFound)
    }

    pub async fn get_all_leases(&self) -> Result<Vec<Lease>, LeaseError> {
        let leases = self.leases.read().await;
        Ok(leases.values().cloned().collect())
    }

    pub async fn get_valid_leases(&self) -> Result<Vec<Lease>, LeaseError> {
        let leases = self.leases.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Ok(leases
            .values()
            .filter(|lease| lease.leased && !lease.probation && lease.expires_at > now)
            .cloned()
            .collect())
    }

    pub async fn is_ip_assigned(&self, ip: Ipv4Addr) -> Result<bool, LeaseError> {
        let leases = self.leases.read().await;
        Ok(leases
            .get(&ip)
            .map(|lease| lease.leased || lease.probation)
            .unwrap_or(false))
    }

    pub async fn update_lease_expiry(&self, ip: Ipv4Addr, expires_at: i64) -> Result<(), LeaseError> {
        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get_mut(&ip) {
                lease.expires_at = expires_at;
            } else {
                return Err(LeaseError::NotFound);
            }
        }
        self.flush().await
    }

    pub async fn mark_ip_declined(&self, ip: Ipv4Addr) -> Result<(), LeaseError> {
        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get_mut(&ip) {
                lease.probation = true;
                lease.leased = false;
            } else {
                // Create a new entry for declined IP if it doesn't exist
                let lease = Lease {
                    ip,
                    client_id: Vec::new(),
                    leased: false,
                    expires_at: 0,
                    network: 0,
                    probation: true,
                };
                leases.insert(ip, lease);
            }
        }
        self.flush().await
    }

    pub async fn release_lease(&self, ip: Ipv4Addr, client_id: &Vec<u8>) -> Result<(), LeaseError> {
        {
            let mut leases = self.leases.write().await;
            if let Some(lease) = leases.get(&ip) {
                if &lease.client_id == client_id {
                    leases.remove(&ip);
                } else {
                    return Err(LeaseError::ClientMismatch);
                }
            }
        }
        self.flush().await
    }
}
