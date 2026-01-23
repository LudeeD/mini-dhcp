//! One-time migration from SQLite database to CSV format.
//!
//! This module provides functionality to migrate lease data from the old
//! SQLite database format (`dhcp.db`) to the new CSV format (`leases.csv`).

#[cfg(feature = "migrate-sqlite")]
use std::net::Ipv4Addr;
use std::path::Path;

/// Result of the migration attempt.
#[derive(Debug, PartialEq)]
pub enum MigrationResult {
    /// Migration completed successfully, N leases migrated.
    Migrated(usize),
    /// Migration skipped because CSV file already exists.
    Skipped,
    /// No SQLite database found, starting fresh.
    NoDatabase,
    /// Migration failed with an error message.
    Failed(String),
}

/// Check if migration is needed and perform it if so.
///
/// Migration logic:
/// - If CSV file exists: skip migration (already using CSV)
/// - If SQLite database exists: migrate to CSV, rename db to .migrated
/// - Otherwise: start fresh (no data)
pub fn maybe_migrate(csv_path: &Path) -> MigrationResult {
    // If CSV already exists, skip migration
    if csv_path.exists() {
        return MigrationResult::Skipped;
    }

    // Derive SQLite path from CSV path (same directory, named "dhcp.db")
    let db_path = csv_path
        .parent()
        .map(|p| p.join("dhcp.db"))
        .unwrap_or_else(|| std::path::PathBuf::from("dhcp.db"));

    // If SQLite database doesn't exist, start fresh
    if !db_path.exists() {
        return MigrationResult::NoDatabase;
    }

    // Perform migration
    #[cfg(feature = "migrate-sqlite")]
    {
        migrate_sqlite_to_csv(&db_path, csv_path)
    }

    #[cfg(not(feature = "migrate-sqlite"))]
    {
        MigrationResult::Failed(
            "SQLite migration not available (compile with migrate-sqlite feature)".to_string(),
        )
    }
}

/// Migrate lease data from SQLite database to CSV format.
#[cfg(feature = "migrate-sqlite")]
fn migrate_sqlite_to_csv(db_path: &Path, csv_path: &Path) -> MigrationResult {
    use rusqlite::Connection;

    // Open SQLite database
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => return MigrationResult::Failed(format!("Failed to open SQLite database: {}", e)),
    };

    // Query all leases from SQLite
    let mut stmt = match conn.prepare("SELECT ip, client_id, leased, expires_at, network, probation FROM leases") {
        Ok(s) => s,
        Err(e) => return MigrationResult::Failed(format!("Failed to prepare query: {}", e)),
    };

    let leases: Vec<CsvLease> = match stmt.query_map([], |row| {
        let ip_int: u32 = row.get(0)?;
        let client_id_blob: Vec<u8> = row.get(1)?;
        let leased_int: i32 = row.get(2)?;
        let expires_at: i64 = row.get(3)?;
        let network: i64 = row.get(4)?;
        let probation_int: i32 = row.get(5)?;

        Ok(CsvLease {
            ip: Ipv4Addr::from(ip_int).to_string(),
            client_id: format_mac(&client_id_blob),
            leased: leased_int != 0,
            expires_at,
            network,
            probation: probation_int != 0,
        })
    }) {
        Ok(rows) => {
            let mut leases = Vec::new();
            for row in rows {
                match row {
                    Ok(lease) => leases.push(lease),
                    Err(e) => return MigrationResult::Failed(format!("Failed to read row: {}", e)),
                }
            }
            leases
        }
        Err(e) => return MigrationResult::Failed(format!("Failed to query leases: {}", e)),
    };

    let lease_count = leases.len();

    // Write to CSV
    let mut writer = match csv::Writer::from_path(csv_path) {
        Ok(w) => w,
        Err(e) => return MigrationResult::Failed(format!("Failed to create CSV file: {}", e)),
    };

    for lease in &leases {
        if let Err(e) = writer.serialize(lease) {
            // Clean up partial CSV file
            let _ = std::fs::remove_file(csv_path);
            return MigrationResult::Failed(format!("Failed to write lease to CSV: {}", e));
        }
    }

    if let Err(e) = writer.flush() {
        let _ = std::fs::remove_file(csv_path);
        return MigrationResult::Failed(format!("Failed to flush CSV: {}", e));
    }

    // Rename SQLite database to mark it as migrated
    let migrated_path = db_path.with_extension("db.migrated");
    if let Err(e) = std::fs::rename(db_path, &migrated_path) {
        // Migration succeeded but rename failed - not critical
        tracing::warn!(
            "Migration succeeded but failed to rename {:?} to {:?}: {}",
            db_path,
            migrated_path,
            e
        );
    }

    MigrationResult::Migrated(lease_count)
}

/// Format MAC address bytes as colon-separated hex string.
#[cfg(feature = "migrate-sqlite")]
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Lease structure for CSV serialization during migration.
#[cfg(feature = "migrate-sqlite")]
#[derive(serde::Serialize)]
struct CsvLease {
    ip: String,
    client_id: String,
    leased: bool,
    expires_at: i64,
    network: i64,
    probation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_skipped_when_csv_exists() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("leases.csv");

        // Create an empty CSV file
        std::fs::write(&csv_path, "").unwrap();

        let result = maybe_migrate(&csv_path);
        assert_eq!(result, MigrationResult::Skipped);
    }

    #[test]
    fn test_no_database_when_neither_exists() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("leases.csv");

        // Neither CSV nor SQLite exists
        let result = maybe_migrate(&csv_path);
        assert_eq!(result, MigrationResult::NoDatabase);
    }

    #[cfg(feature = "migrate-sqlite")]
    #[test]
    fn test_migration_from_sqlite() {
        use rusqlite::Connection;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("dhcp.db");
        let csv_path = temp_dir.path().join("leases.csv");

        // Create SQLite database with test data
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE leases (
                ip INTEGER PRIMARY KEY,
                client_id BLOB,
                leased INTEGER,
                expires_at INTEGER,
                network INTEGER,
                probation INTEGER
            )",
            [],
        )
        .unwrap();

        // Insert test lease: 192.168.1.100 = 0xC0A80164 = 3232235876
        let ip: u32 = Ipv4Addr::new(192, 168, 1, 100).into();
        let client_id: Vec<u8> = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        conn.execute(
            "INSERT INTO leases (ip, client_id, leased, expires_at, network, probation) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![ip, client_id, 1, 1700000000i64, 0i64, 0],
        )
        .unwrap();

        drop(conn);

        // Perform migration
        let result = maybe_migrate(&csv_path);
        assert_eq!(result, MigrationResult::Migrated(1));

        // Verify CSV was created
        assert!(csv_path.exists());

        // Verify SQLite was renamed
        assert!(!db_path.exists());
        assert!(temp_dir.path().join("dhcp.db.migrated").exists());

        // Verify CSV content
        let csv_content = std::fs::read_to_string(&csv_path).unwrap();
        assert!(csv_content.contains("192.168.1.100"));
        assert!(csv_content.contains("aa:bb:cc:dd:ee:ff"));
        assert!(csv_content.contains("true")); // leased
    }

    #[cfg(feature = "migrate-sqlite")]
    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(format_mac(&[]), "");
        assert_eq!(format_mac(&[0x01]), "01");
    }

    #[cfg(feature = "migrate-sqlite")]
    #[test]
    fn test_migration_empty_database() {
        use rusqlite::Connection;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("dhcp.db");
        let csv_path = temp_dir.path().join("leases.csv");

        // Create empty SQLite database
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE leases (
                ip INTEGER PRIMARY KEY,
                client_id BLOB,
                leased INTEGER,
                expires_at INTEGER,
                network INTEGER,
                probation INTEGER
            )",
            [],
        )
        .unwrap();
        drop(conn);

        let result = maybe_migrate(&csv_path);
        assert_eq!(result, MigrationResult::Migrated(0));
        assert!(csv_path.exists());
    }
}
