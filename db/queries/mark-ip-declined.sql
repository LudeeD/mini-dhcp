UPDATE leases
SET probation = 1, leased = 0
WHERE ip = ?;
