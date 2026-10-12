-- Network seeds of attack surface discovery: AS numbers and organization
-- names the organization asserts are its own
-- (docs/rfcs/RFC-082-network-seeds.md). A seed never authorizes a probe;
-- its expansion (announced prefixes, candidate AS numbers from public
-- routing data) is offered for a person to add through the scope flow.
CREATE TABLE easm_network_seeds (
    id               UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id        UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind             VARCHAR(10)  NOT NULL,
    value            VARCHAR(200) NOT NULL,
    label            VARCHAR(200) NOT NULL DEFAULT '',
    holder           VARCHAR(300) NOT NULL DEFAULT '',
    prefixes         TEXT[]       NOT NULL DEFAULT '{}',
    suggestions      JSONB        NOT NULL DEFAULT '[]'::jsonb,
    last_expanded_at TIMESTAMPTZ,
    expand_error     VARCHAR(300) NOT NULL DEFAULT '',
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_easm_network_seeds PRIMARY KEY (id),
    CONSTRAINT chk_easm_network_seeds_kind CHECK (kind IN ('asn', 'org_name')),
    CONSTRAINT chk_easm_network_seeds_prefixes CHECK (cardinality(prefixes) <= 1000),
    CONSTRAINT chk_easm_network_seeds_suggestions CHECK (jsonb_typeof(suggestions) = 'array' AND jsonb_array_length(suggestions) <= 50)
);
COMMENT ON TABLE easm_network_seeds IS
    'RFC-082: AS number and organization seeds of EASM discovery; never an authorization to probe';

CREATE UNIQUE INDEX uq_easm_network_seeds_value ON easm_network_seeds (tenant_id, kind, lower(value));
CREATE INDEX idx_easm_network_seeds_expand ON easm_network_seeds (last_expanded_at NULLS FIRST);
