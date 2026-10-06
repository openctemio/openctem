-- Per-task logs from sensors (sensor protocol v2, POST
-- /api/v2/sensor/commands/{id}/logs; RFC-029 §4.4.1).
--
-- A sensor sends what a task's tool logged in numbered batches through its
-- outbox. One row per batch, keyed by (command_id, seq), so a batch replayed
-- after an outage is stored once. seq -1 is the per-command drop counter: the
-- lines refused by the per-command caps (200 batches, 2 MiB), so the run page
-- can say the log was cut.
--
-- Operational data, not evidence: kept 14 days (the command-log retention
-- controller) and deleted with its command. A new, empty table: no lock on
-- any populated table beyond the FK checks of new rows.

CREATE TABLE IF NOT EXISTS command_logs (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    command_id UUID NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    seq        INT NOT NULL,
    lines      JSONB NOT NULL DEFAULT '[]'::jsonb,
    line_count INT NOT NULL DEFAULT 0,
    bytes      INT NOT NULL DEFAULT 0,
    dropped    INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (command_id, seq),
    CONSTRAINT chk_command_logs_seq CHECK (seq >= -1 AND seq < 10000),
    CONSTRAINT chk_command_logs_lines CHECK (jsonb_typeof(lines) = 'array'),
    CONSTRAINT chk_command_logs_counts CHECK (line_count >= 0 AND bytes >= 0 AND dropped >= 0)
);

-- Reads of one task's log are tenant-scoped.
CREATE INDEX IF NOT EXISTS idx_command_logs_tenant_command ON command_logs (tenant_id, command_id);

-- The retention sweep.
CREATE INDEX IF NOT EXISTS idx_command_logs_created_at ON command_logs (created_at);

COMMENT ON TABLE command_logs IS 'Per-task log batches sent by sensors (RFC-029 §4.4.1); kept 14 days.';
