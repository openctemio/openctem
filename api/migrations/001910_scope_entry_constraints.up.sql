-- Port and protocol limits of a scope entry (RFC-065 §16.8).
--
-- A program can list a service ("api.example.com:8443/tcp") rather than a
-- whole host. ports and protocol limit such an entry: it covers a target
-- only when the target names an allowed port over the allowed protocol, so
-- it never authorizes a scan of the whole host. The limit is part of the
-- entry's identity: two entries may name the same host with different ports.
--
-- Live impact: two columns with constant defaults (no rewrite); the unique
-- key is rebuilt with the new columns (every existing row has the empty
-- default, so it holds).

ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS ports    text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS protocol text NOT NULL DEFAULT '';

ALTER TABLE scope_targets
    ADD CONSTRAINT chk_scope_targets_protocol CHECK (protocol IN ('', 'tcp', 'udp')),
    ADD CONSTRAINT chk_scope_targets_ports CHECK (
        length(ports) <= 400
        AND ports ~ '^([0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*)?$');

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS unique_scope_target;
ALTER TABLE scope_targets
    ADD CONSTRAINT unique_scope_target UNIQUE (tenant_id, target_type, pattern, ports, protocol);
