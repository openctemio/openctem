-- Ticket create policy (docs/architecture/ticket-create-policy.md): which
-- findings the automatic path files as tracker issues, per integration; the
-- findings it held back and why; and a per-day counter for the daily cap.
--
-- Live impact: three new, empty tables. An integration without a policy row
-- uses the built-in defaults.

CREATE TABLE IF NOT EXISTS ticket_create_policies (
    tenant_id           uuid        NOT NULL,
    integration_id      uuid        NOT NULL,
    min_severity        varchar(16) NOT NULL DEFAULT 'medium',
    min_priority_class  varchar(4)  NOT NULL DEFAULT 'P2',
    always_kev          boolean     NOT NULL DEFAULT true,
    daily_cap           integer     NOT NULL DEFAULT 200,
    updated_by          uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ticket_create_policies PRIMARY KEY (tenant_id, integration_id),
    CONSTRAINT fk_ticket_create_policies_integration_tenant FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_create_policies_updated_by FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_ticket_create_policies_severity
        CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT chk_ticket_create_policies_priority
        CHECK (min_priority_class IN ('', 'P0', 'P1', 'P2', 'P3')),
    CONSTRAINT chk_ticket_create_policies_cap CHECK (daily_cap BETWEEN 0 AND 10000)
);

COMMENT ON TABLE ticket_create_policies IS
    'Which findings the automatic path files as issues on one tracker integration; no row means the defaults.';

CREATE TABLE IF NOT EXISTS ticket_create_holds (
    tenant_id       uuid         NOT NULL,
    integration_id  uuid         NOT NULL,
    finding_id      uuid         NOT NULL,
    reason          varchar(32)  NOT NULL,
    detail          varchar(500) NOT NULL DEFAULT '',
    held_at         timestamptz  NOT NULL DEFAULT now(),
    checked_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_ticket_create_holds PRIMARY KEY (tenant_id, integration_id, finding_id),
    CONSTRAINT fk_ticket_create_holds_integration_tenant FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_ticket_create_holds_finding_tenant FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ticket_create_holds_reason
        CHECK (reason IN ('below_threshold', 'daily_cap', 'create_failed'))
);

CREATE INDEX IF NOT EXISTS idx_ticket_create_holds_finding
    ON ticket_create_holds (tenant_id, finding_id);
CREATE INDEX IF NOT EXISTS idx_ticket_create_holds_checked
    ON ticket_create_holds (checked_at);

COMMENT ON TABLE ticket_create_holds IS
    'Findings the automatic ticket path held back (below the policy, over the daily cap, or a failed create); re-checked when the finding changes.';

CREATE TABLE IF NOT EXISTS ticket_create_daily (
    tenant_id       uuid    NOT NULL,
    integration_id  uuid    NOT NULL,
    day             date    NOT NULL,
    created         integer NOT NULL DEFAULT 0,
    CONSTRAINT pk_ticket_create_daily PRIMARY KEY (tenant_id, integration_id, day),
    CONSTRAINT fk_ticket_create_daily_integration_tenant FOREIGN KEY (tenant_id, integration_id)
        REFERENCES integrations (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ticket_create_daily_created CHECK (created >= 0)
);

COMMENT ON TABLE ticket_create_daily IS
    'Issues the automatic path created per integration and UTC day, for the daily cap.';
