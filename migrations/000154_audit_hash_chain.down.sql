-- Drop the hash-chain side table. Existing audit_logs rows remain
-- untouched; only the cryptographic chain is lost.
DROP TABLE IF EXISTS audit_log_chain;
