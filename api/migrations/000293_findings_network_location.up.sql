-- Where on the network a finding was observed: the port, its transport and
-- the service on it, from CTIS Finding.Network (host, port, protocol,
-- service). Ingest used the port only inside the network-VA dedup
-- fingerprint (processor_findings.go networkVACVEKey) and dropped it, so no
-- stored finding knew its port and "issues on this service" could not be
-- answered (RFC-042 F6).
--
-- These columns are NOT fingerprint inputs. Existing rows stay NULL; they get
-- a value on their next sighting (first writer wins, NULL is filled).
-- No index yet: nothing queries by port until RFC-042 services land.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS network_port INTEGER
        CONSTRAINT chk_findings_network_port CHECK (network_port BETWEEN 1 AND 65535),
    ADD COLUMN IF NOT EXISTS network_transport VARCHAR(8)
        CONSTRAINT chk_findings_network_transport CHECK (network_transport IN ('tcp', 'udp', 'sctp')),
    ADD COLUMN IF NOT EXISTS network_service VARCHAR(64);

COMMENT ON COLUMN findings.network_port IS 'Port the finding was observed on (CTIS Finding.Network.Port); NULL = not port-specific or unknown. Not a fingerprint input.';
COMMENT ON COLUMN findings.network_transport IS 'Transport of network_port: tcp, udp or sctp.';
COMMENT ON COLUMN findings.network_service IS 'Service on network_port as the scanner named it (https, ssh, ...).';
