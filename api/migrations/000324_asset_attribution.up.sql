-- Asset attribution and its evidence (RFC-036 §6.4, owner decision O4).
--
-- asset_attributions holds, per asset, whether the platform believes it is
-- the tenant's: state, confidence 0-100 and the strongest rule. An asset
-- without a row is a legacy asset and counts as confirmed, so nothing in the
-- inventory changes meaning when this table appears.
--
-- It is a side table rather than columns on assets on purpose: the asset
-- write paths (create, update, batch upsert) each list their columns, and a
-- column one of them forgets is silently dropped. Attribution is written in
-- one place, by the EASM collectors and by human decisions.
--
-- easm_evidence is one row per (asset, rule, source): the typed reason, the
-- collector or sensor that observed it, and the observed datum. A re-sighting
-- updates last_observed_at; it is not new evidence.
CREATE TABLE IF NOT EXISTS asset_attributions (
    asset_id      UUID        PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    state         TEXT        NOT NULL,
    confidence    SMALLINT    NOT NULL,
    reason        TEXT        NOT NULL DEFAULT '',
    decided_by    UUID        REFERENCES users(id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_asset_attributions_state CHECK (state IN
        ('confirmed', 'needs_review', 'candidate', 'dependency', 'monitor_only', 'rejected')),
    CONSTRAINT chk_asset_attributions_confidence CHECK (confidence BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_asset_attributions_tenant_state
    ON asset_attributions (tenant_id, state);

CREATE TABLE IF NOT EXISTS easm_evidence (
    id                UUID        PRIMARY KEY,
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id          UUID        NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rule              TEXT        NOT NULL,
    technique         TEXT        NOT NULL,
    source            TEXT        NOT NULL,
    weight            REAL        NOT NULL,
    observed          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_observed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_easm_evidence_asset_rule_source UNIQUE (asset_id, rule, source),
    CONSTRAINT chk_easm_evidence_weight CHECK (weight BETWEEN -1 AND 1)
);

CREATE INDEX IF NOT EXISTS idx_easm_evidence_tenant_asset
    ON easm_evidence (tenant_id, asset_id);
