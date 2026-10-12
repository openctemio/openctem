-- Passive lookalike-domain monitoring (docs/rfcs/RFC-083-lookalike-domains.md).
-- A watch is one of the organization's root domains with its settings; the
-- candidates are the generated lookalikes and what the passive checks (DNS,
-- Certificate Transparency) last saw. A registered candidate is an exposure
-- of type lookalike_domain.
CREATE TABLE easm_lookalike_watches (
    id             UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id      UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain         VARCHAR(253) NOT NULL,
    enabled        BOOLEAN      NOT NULL DEFAULT true,
    techniques     TEXT[]       NOT NULL DEFAULT '{}',
    max_candidates INTEGER      NOT NULL DEFAULT 300,
    generated_at   TIMESTAMPTZ,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_easm_lookalike_watches PRIMARY KEY (id),
    CONSTRAINT uq_easm_lookalike_watches_domain UNIQUE (tenant_id, domain),
    CONSTRAINT chk_easm_lookalike_watches_max CHECK (max_candidates BETWEEN 10 AND 1000),
    CONSTRAINT chk_easm_lookalike_watches_techniques CHECK (cardinality(techniques) <= 20)
);
COMMENT ON TABLE easm_lookalike_watches IS
    'RFC-083: root domains watched for lookalikes (passive checks only)';

CREATE TABLE easm_lookalike_candidates (
    tenant_id     UUID         NOT NULL,
    watch_id      UUID         NOT NULL REFERENCES easm_lookalike_watches(id) ON DELETE CASCADE,
    domain        VARCHAR(253) NOT NULL,
    technique     VARCHAR(20)  NOT NULL,
    state         VARCHAR(12)  NOT NULL DEFAULT 'unchecked',
    has_a         BOOLEAN      NOT NULL DEFAULT false,
    has_mx        BOOLEAN      NOT NULL DEFAULT false,
    name_servers  TEXT[]       NOT NULL DEFAULT '{}',
    ct_certs      INTEGER      NOT NULL DEFAULT 0,
    ct_checked_at TIMESTAMPTZ,
    first_registered_at TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_easm_lookalike_candidates PRIMARY KEY (tenant_id, watch_id, domain),
    CONSTRAINT chk_easm_lookalike_candidates_state CHECK (state IN ('unchecked', 'unregistered', 'registered')),
    CONSTRAINT chk_easm_lookalike_candidates_ns CHECK (cardinality(name_servers) <= 13)
);
CREATE INDEX idx_easm_lookalike_candidates_due ON easm_lookalike_candidates (tenant_id, watch_id, last_checked_at NULLS FIRST);
CREATE INDEX idx_easm_lookalike_candidates_registered ON easm_lookalike_candidates (tenant_id, state) WHERE state = 'registered';

-- The exposure type. NOT VALID + VALIDATE keeps writes going on a large table.
ALTER TABLE exposure_events DROP CONSTRAINT chk_exposure_events_type;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_type CHECK (event_type IN (
    'port_open', 'port_closed', 'service_detected', 'service_changed', 'subdomain_discovered', 'subdomain_removed',
    'certificate_expiring', 'certificate_expired', 'bucket_public', 'bucket_private', 'repo_public', 'repo_private',
    'api_exposed', 'api_removed', 'credential_leaked', 'sensitive_data_exposed', 'misconfiguration', 'dns_change',
    'ssl_issue', 'header_missing', 'identity_mfa_gap', 'identity_stale_principal', 'identity_overprivileged',
    'dangling_cname', 'dangling_ns', 'email_security_weak', 'subdomain_takeover', 'lookalike_domain', 'custom')) NOT VALID;
ALTER TABLE exposure_events VALIDATE CONSTRAINT chk_exposure_events_type;
