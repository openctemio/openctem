-- Children follow their host (research/117 F1, RFC-036 §6.4): a service, a
-- certificate or a web endpoint takes the attribution state of the host it
-- was seen on. follows_host_id names that host; while it is set, the child's
-- automatic record carries the host's state, the review queue lists it under
-- the host instead of as its own row, and a person's decision on the child
-- itself clears the link.
--
-- The host is always an asset of the same tenant (composite foreign key);
-- deleting the host only clears the link.

ALTER TABLE asset_attributions
    ADD COLUMN follows_host_id UUID;

ALTER TABLE asset_attributions
    ADD CONSTRAINT fk_asset_attributions_follows_host
        FOREIGN KEY (tenant_id, follows_host_id) REFERENCES assets (tenant_id, id)
        ON DELETE SET NULL (follows_host_id);

ALTER TABLE asset_attributions
    ADD CONSTRAINT chk_asset_attributions_follows_other
        CHECK (follows_host_id IS NULL OR follows_host_id <> asset_id);

CREATE INDEX idx_asset_attributions_follows_host
    ON asset_attributions (tenant_id, follows_host_id)
    WHERE follows_host_id IS NOT NULL;

-- One-time backfill, idempotent: pending automatic children whose host is
-- pending too are linked to that host. Only a stored relationship of the
-- same tenant links (exposes: host -> service; serves_certificate: service
-- -> certificate, which follows the service's host), only when exactly one
-- such host exists, and no state changes. Rows already linked or decided by
-- a person are left alone.

-- Services under the address or name that exposes them.
WITH cand AS (
    SELECT c.asset_id, min(r.source_asset_id::text)::uuid AS host_id, count(DISTINCT r.source_asset_id) AS n
    FROM asset_attributions c
    JOIN assets ca ON ca.id = c.asset_id AND ca.tenant_id = c.tenant_id
    JOIN asset_relationships r
        ON r.tenant_id = c.tenant_id AND r.target_asset_id = c.asset_id AND r.relationship_type = 'exposes'
    JOIN asset_attributions h
        ON h.tenant_id = c.tenant_id AND h.asset_id = r.source_asset_id
    WHERE c.follows_host_id IS NULL
      AND c.decided_at IS NULL
      AND c.state IN ('needs_review', 'candidate')
      AND ca.asset_type = 'service'
      AND h.decided_at IS NULL
      AND h.state IN ('needs_review', 'candidate')
      AND h.follows_host_id IS NULL
    GROUP BY c.asset_id
)
UPDATE asset_attributions c
SET follows_host_id = cand.host_id
FROM cand
WHERE c.asset_id = cand.asset_id AND cand.n = 1 AND c.follows_host_id IS NULL;

-- Certificates under the host of the service that served them (or the
-- service itself when it has no host of its own).
WITH cand AS (
    SELECT c.asset_id,
           min(COALESCE(s.follows_host_id, s.asset_id)::text)::uuid AS host_id,
           count(DISTINCT COALESCE(s.follows_host_id, s.asset_id)) AS n
    FROM asset_attributions c
    JOIN assets ca ON ca.id = c.asset_id AND ca.tenant_id = c.tenant_id
    JOIN asset_relationships r
        ON r.tenant_id = c.tenant_id AND r.target_asset_id = c.asset_id AND r.relationship_type = 'serves_certificate'
    JOIN asset_attributions s
        ON s.tenant_id = c.tenant_id AND s.asset_id = r.source_asset_id
    WHERE c.follows_host_id IS NULL
      AND c.decided_at IS NULL
      AND c.state IN ('needs_review', 'candidate')
      AND ca.asset_type = 'certificate'
      AND s.decided_at IS NULL
      AND s.state IN ('needs_review', 'candidate')
    GROUP BY c.asset_id
)
UPDATE asset_attributions c
SET follows_host_id = cand.host_id
FROM cand
WHERE c.asset_id = cand.asset_id AND cand.n = 1 AND c.follows_host_id IS NULL;
