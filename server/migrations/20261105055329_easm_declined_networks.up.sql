-- Networks the organization answered "not ours" on the Decisions card
-- (research/425 §5.4): the addresses its in-scope names resolve to inside
-- such a network are no longer offered, and the question is not asked again.
-- A row only narrows what is offered; it never authorizes anything. Removing
-- it (Undo) asks again.
CREATE TABLE IF NOT EXISTS easm_declined_networks (
    id         UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind       VARCHAR(16) NOT NULL,
    value      TEXT        NOT NULL,
    label      TEXT        NOT NULL DEFAULT '',
    created_by UUID        NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_easm_declined_networks_kind CHECK (kind IN ('asn', 'org_name')),
    CONSTRAINT uq_easm_declined_networks UNIQUE (tenant_id, kind, value)
);
