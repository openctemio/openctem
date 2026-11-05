-- The secrets a claimed job may use (docs/architecture/task-secrets.md): one
-- row per command and lease epoch, written when a sensor claims a scan,
-- retest, validate or proxy test job, with the refs listed in the job's
-- signed payload (member "secrets"). The task secrets fetch answers only
-- refs recorded here, only to this sensor under this lease epoch, and at
-- most max_fetches times. The row holds names, never a value.
--
-- Live impact: a new, empty table; no lock on commands, nothing to backfill.
CREATE TABLE command_secret_grants (
    command_id  uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    lease_epoch integer NOT NULL CHECK (lease_epoch > 0),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sensor_id   uuid NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    refs        jsonb NOT NULL CHECK (jsonb_typeof(refs) = 'object'),
    fetches     integer NOT NULL DEFAULT 0 CHECK (fetches >= 0),
    max_fetches integer NOT NULL CHECK (max_fetches BETWEEN 1 AND 256),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (command_id, lease_epoch),
    CONSTRAINT chk_command_secret_grants_fetches CHECK (fetches <= max_fetches)
);

CREATE INDEX idx_command_secret_grants_tenant ON command_secret_grants (tenant_id);

COMMENT ON TABLE command_secret_grants IS 'Secret refs a claimed job may fetch (names only), per command and lease epoch, with the bounded fetch counter.';
