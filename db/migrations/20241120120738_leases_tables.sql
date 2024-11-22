CREATE TABLE IF NOT EXISTS leases(
    ip INTEGER NOT NULL,
    client_id BLOB NOT NULL,
    leased BOOLEAN NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    network INTEGER NOT NULL,
    probation BOOLEAN NOT NULL DEFAULT 0,
    PRIMARY KEY(ip)
);
CREATE INDEX idx_ip_expires on leases (ip, expires_at);
