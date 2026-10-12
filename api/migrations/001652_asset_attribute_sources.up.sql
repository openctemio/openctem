-- Asset attribute reconciliation (RFC-069): each source's latest value of a
-- tracked asset attribute, so the asset shows the value of the most trusted,
-- most recent source instead of whichever write came first or last.
CREATE TABLE asset_attribute_sources (
    tenant_id    UUID         NOT NULL,
    asset_id     UUID         NOT NULL,
    attribute    VARCHAR(40)  NOT NULL,
    source_kind  VARCHAR(20)  NOT NULL,
    source_name  VARCHAR(100) NOT NULL DEFAULT '',
    value        VARCHAR(500) NOT NULL DEFAULT '',
    observed_at  TIMESTAMPTZ  NOT NULL,
    ingested_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    confidence   SMALLINT     NOT NULL DEFAULT 100,
    CONSTRAINT pk_asset_attribute_sources PRIMARY KEY (tenant_id, asset_id, attribute, source_kind, source_name),
    CONSTRAINT fk_asset_attribute_sources_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_attribute_sources_attribute
        CHECK (attribute IN ('criticality', 'owner_ref', 'exposure', 'data_classification')),
    CONSTRAINT chk_asset_attribute_sources_kind
        CHECK (source_kind IN ('manual', 'integration', 'import', 'scan')),
    CONSTRAINT chk_asset_attribute_sources_confidence CHECK (confidence BETWEEN 0 AND 100),
    CONSTRAINT chk_asset_attribute_sources_observed CHECK (observed_at <= ingested_at + interval '1 minute')
);
COMMENT ON TABLE asset_attribute_sources IS
    'RFC-069: per-source latest value of a reconciled asset attribute. A manual row is a lock that wins until released. assets holds the resolved value.';

-- Values people set before this table existed stay as they are: they become
-- locks (released from the asset page). Values ingest filled in get no row and
-- are kept until a trusted source reports the attribute.
--
-- 1. Assets a person created (no discovery source, or "manual").
INSERT INTO asset_attribute_sources (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at)
SELECT a.tenant_id, a.id, v.attribute, 'manual', 'upgrade', v.value, LEAST(a.updated_at, now()), now()
  FROM assets a
 CROSS JOIN LATERAL (VALUES
        ('criticality', a.criticality::text),
        ('owner_ref', NULLIF(a.owner_ref, '')),
        ('exposure', NULLIF(a.exposure::text, 'unknown')),
        ('data_classification', NULLIF(a.data_classification, ''))
     ) AS v(attribute, value)
 WHERE COALESCE(a.discovery_source, '') IN ('', 'manual')
   AND v.value IS NOT NULL
ON CONFLICT DO NOTHING;

-- 2. Any asset whose attribute a person changed (state history).
INSERT INTO asset_attribute_sources (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at)
SELECT DISTINCT a.tenant_id, a.id, h.field, 'manual', 'upgrade',
       CASE h.field
           WHEN 'criticality' THEN a.criticality::text
           WHEN 'owner_ref' THEN COALESCE(a.owner_ref, '')
           WHEN 'exposure' THEN a.exposure::text
           ELSE COALESCE(a.data_classification, '')
       END,
       LEAST(a.updated_at, now()), now()
  FROM asset_state_history h
  JOIN assets a ON a.tenant_id = h.tenant_id AND a.id = h.asset_id
 WHERE h.source = 'manual'
   AND h.field IN ('criticality', 'owner_ref', 'exposure', 'data_classification')
ON CONFLICT DO NOTHING;
