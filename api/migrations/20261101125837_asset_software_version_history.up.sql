-- Version history of a product at a place on an asset
-- (docs/architecture/software-version-history.md).
--
-- Every version a source reports at (asset, product, location) already has
-- its own asset_software row with first and last seen. These columns add
-- what decides which one is current: the evidence class, the number of
-- sightings, the streak of consecutive scans a version was the trusted
-- reading of, and the role of the row (established or candidate). A new
-- version starts as a candidate and supersedes the established one only on
-- strong evidence or after several consecutive readings, so one weak
-- sighting never closes a finding.
--
-- Safe on populated tables: columns with constant defaults are metadata
-- only; the checks are added NOT VALID and validated without blocking
-- writes. Every existing row stays established.

ALTER TABLE asset_software
    ADD COLUMN version_state  TEXT        NOT NULL DEFAULT 'established',
    ADD COLUMN evidence_class TEXT        NOT NULL DEFAULT 'banner',
    ADD COLUMN sightings      INTEGER     NOT NULL DEFAULT 1,
    ADD COLUMN streak         SMALLINT    NOT NULL DEFAULT 1,
    ADD COLUMN streak_since   TIMESTAMPTZ;

ALTER TABLE asset_software ADD CONSTRAINT chk_asset_software_version_state
    CHECK (version_state IN ('established', 'candidate')) NOT VALID;
ALTER TABLE asset_software ADD CONSTRAINT chk_asset_software_evidence_class
    CHECK (evidence_class IN ('inventory', 'sbom', 'probe', 'banner', 'heuristic')) NOT VALID;
ALTER TABLE asset_software ADD CONSTRAINT chk_asset_software_sightings
    CHECK (sightings >= 1) NOT VALID;
ALTER TABLE asset_software ADD CONSTRAINT chk_asset_software_streak
    CHECK (streak BETWEEN 0 AND 1000) NOT VALID;
ALTER TABLE asset_software VALIDATE CONSTRAINT chk_asset_software_version_state;
ALTER TABLE asset_software VALIDATE CONSTRAINT chk_asset_software_evidence_class;
ALTER TABLE asset_software VALIDATE CONSTRAINT chk_asset_software_sightings;
ALTER TABLE asset_software VALIDATE CONSTRAINT chk_asset_software_streak;

COMMENT ON COLUMN asset_software.version_state IS
    'established: the version findings are built on (one per asset, product and location, not superseded); candidate: seen, not yet trusted to replace it.';
COMMENT ON COLUMN asset_software.evidence_class IS
    'Strongest way a source knew this version: inventory, sbom, probe, banner, heuristic.';
COMMENT ON COLUMN asset_software.sightings IS 'Distinct observation times of this version here.';
COMMENT ON COLUMN asset_software.streak IS
    'Consecutive scans this version was the trusted reading of, since streak_since (0 after another version won a scan).';
COMMENT ON COLUMN asset_software.superseded_at IS
    'When another version became established at the same location (the observation time of the reading that confirmed it).';

-- Evidence class of the existing network rows (packages are always
-- authoritative inventory and never go through the version history).
UPDATE asset_software SET evidence_class = CASE
        WHEN source = 'os' THEN 'heuristic'
        WHEN source IN ('service', 'open_port') AND confidence >= 80 THEN 'probe'
        ELSE 'banner' END
    WHERE source <> 'package';
UPDATE asset_software SET evidence_class = CASE WHEN channel IN ('sbom_upload', 'ci') THEN 'sbom' ELSE 'inventory' END
    WHERE source = 'package';

-- Repair: a version that superseded the previous one on a single weak
-- sighting (below confidence 80, seen within 12 hours) becomes a candidate,
-- and the version it superseded is established again. The next matcher pass
-- then cancels the close proposals that sighting produced.
WITH demoted AS (
    UPDATE asset_software n
    SET version_state = 'candidate', streak_since = n.first_seen_at, updated_at = now()
    WHERE n.source <> 'package' AND n.superseded_at IS NULL AND n.confidence < 80
      AND n.last_seen_at - n.first_seen_at < interval '12 hours'
      AND EXISTS (
          SELECT 1 FROM asset_software o
          WHERE o.tenant_id = n.tenant_id AND o.asset_id = n.asset_id AND o.product_id = n.product_id
            AND o.location = n.location AND o.id <> n.id
            AND o.superseded_at IS NOT NULL AND o.superseded_at >= n.first_seen_at)
    RETURNING n.tenant_id, n.asset_id, n.product_id, n.location, n.first_seen_at
)
UPDATE asset_software o SET superseded_at = NULL, updated_at = now()
FROM demoted d
WHERE o.id = (
    SELECT p.id FROM asset_software p
    WHERE p.tenant_id = d.tenant_id AND p.asset_id = d.asset_id AND p.product_id = d.product_id
      AND p.location = d.location AND p.superseded_at >= d.first_seen_at
    ORDER BY p.last_seen_at DESC, p.id
    LIMIT 1);

CREATE INDEX idx_asset_software_established ON asset_software (tenant_id, asset_id, product_id, location)
    WHERE version_state = 'established' AND superseded_at IS NULL;
