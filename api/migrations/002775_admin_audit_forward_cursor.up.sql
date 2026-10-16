-- Where the off-box admin audit forwarder stands: the chain position and hash
-- of the last row the sink acknowledged. One row per sink set. The cursor only
-- moves forward (the upsert keeps the greater position), so a replica running
-- on a stale read can never rewind it.
CREATE TABLE IF NOT EXISTS admin_audit_forward_cursor (
    name       text PRIMARY KEY,
    position   bigint NOT NULL CHECK (position >= 0),
    hash       text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE admin_audit_forward_cursor IS
    'Last admin_audit_logs chain position acknowledged by the off-box audit sink (ADMIN_AUDIT_FORWARD_*).';
