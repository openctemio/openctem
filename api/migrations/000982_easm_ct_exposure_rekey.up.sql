-- CT exposures get an identity that does not depend on the linked asset
-- (research/22 P0-9, bug 22c B2; docs/architecture/easm.md).
--
-- A CT exposure's fingerprint used to include its asset id, so the same
-- certificate finding was stored once with no asset (seed-only period) and
-- again once a domain asset existed: duplicates that never resolved. The
-- code now fingerprints CT exposures on tenant, type, title and host only
-- (certmonitor.ctFingerprint). This re-keys the stored rows to that
-- identity. Where several rows collapse into one, the active row with an
-- asset and the latest sighting is kept; the others are resolved as
-- duplicates and keep a unique placeholder fingerprint.
--
-- The previous fingerprint, state and resolution of every touched row are
-- kept in easm_ct_rekey_000982 so the down migration restores them.
--
-- The fingerprint below is byte-for-byte what exposure.Fingerprint computes
-- in Go for these rows (json.Marshal of a map sorts keys; CT values are
-- plain ASCII host names); internal/infra/postgres/easm_ct_rekey_db_test.go
-- checks it.

CREATE TABLE IF NOT EXISTS easm_ct_rekey_000982 (
    id                   UUID PRIMARY KEY,
    old_fingerprint      VARCHAR(64) NOT NULL,
    old_state            TEXT        NOT NULL,
    old_resolved_at      TIMESTAMPTZ,
    old_resolution_notes TEXT
);

DROP TABLE IF EXISTS pg_temp.ct_rekey;
CREATE TEMP TABLE ct_rekey ON COMMIT DROP AS
SELECT id, tenant_id, fingerprint, state, resolved_at, resolution_notes, rn, new_fp
FROM (
    SELECT e.id, e.tenant_id, e.fingerprint, e.state, e.resolved_at, e.resolution_notes,
           k.new_fp,
           row_number() OVER (PARTITION BY e.tenant_id, k.new_fp
                              ORDER BY (e.state = 'active') DESC, (e.asset_id IS NOT NULL) DESC,
                                       e.last_seen_at DESC, e.id) AS rn
    FROM exposure_events e
    CROSS JOIN LATERAL (
        SELECT encode(sha256(convert_to(
            '{"domain":' || to_json(e.details->>'domain')::text ||
            ',"event_type":' || to_json(e.event_type::text)::text ||
            ',"source":"cert_transparency"' ||
            ',"tenant_id":' || to_json(e.tenant_id::text)::text ||
            ',"title":' || to_json(e.title::text)::text || '}', 'UTF8')), 'hex') AS new_fp
    ) k
    WHERE e.source = 'cert_transparency' AND e.details ? 'domain'
) x
WHERE fingerprint <> new_fp OR rn > 1;

INSERT INTO easm_ct_rekey_000982 (id, old_fingerprint, old_state, old_resolved_at, old_resolution_notes)
SELECT id, fingerprint, state, resolved_at, resolution_notes FROM ct_rekey
ON CONFLICT (id) DO NOTHING;

-- Duplicates first: they free the target fingerprint.
UPDATE exposure_events e SET
    fingerprint = encode(sha256(convert_to('ct-duplicate:' || e.id::text, 'UTF8')), 'hex'),
    state = CASE WHEN e.state = 'active' THEN 'resolved' ELSE e.state END,
    resolved_at = CASE WHEN e.state = 'active' THEN now() ELSE e.resolved_at END,
    resolution_notes = CASE WHEN e.state = 'active'
        THEN 'Resolved automatically: duplicate of the same Certificate Transparency exposure.'
        ELSE e.resolution_notes END,
    updated_at = now()
FROM ct_rekey r WHERE e.id = r.id AND r.rn > 1;

UPDATE exposure_events e SET fingerprint = r.new_fp, updated_at = now()
FROM ct_rekey r WHERE e.id = r.id AND r.rn = 1 AND e.fingerprint <> r.new_fp;
