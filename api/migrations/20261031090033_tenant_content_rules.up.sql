-- An organization's own detection rules (docs/architecture/rule-packs.md):
-- web fingerprint rules and sensitive-information rules, one row per rule.
-- body is the rule as validated by the API (RE2 pattern, keyword
-- prefilter, size and complexity limits); enabled rules join the
-- organization's engine and no other. version counts content changes;
-- sha256 is of the canonical JSON of body.
CREATE TABLE tenant_content_rules (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        varchar(20)  NOT NULL,
    rule_id     varchar(64)  NOT NULL,
    name        varchar(128) NOT NULL,
    enabled     boolean      NOT NULL DEFAULT true,
    version     integer      NOT NULL DEFAULT 1,
    sha256      char(64)     NOT NULL,
    body        jsonb        NOT NULL,
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    updated_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_tenant_content_rules_rule UNIQUE (tenant_id, kind, rule_id),
    CONSTRAINT chk_tenant_content_rules_kind CHECK (kind IN ('web-fingerprints', 'secret-rules')),
    CONSTRAINT chk_tenant_content_rules_rule_id CHECK (rule_id ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    CONSTRAINT chk_tenant_content_rules_version CHECK (version >= 1),
    CONSTRAINT chk_tenant_content_rules_sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_tenant_content_rules_body CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 16384)
);

COMMENT ON TABLE tenant_content_rules IS 'An organization''s own detection rules (web fingerprints, sensitive information), evaluated on its ingested web content only.';

CREATE POLICY tenant_content_rules_tenant_isolation ON tenant_content_rules
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));
