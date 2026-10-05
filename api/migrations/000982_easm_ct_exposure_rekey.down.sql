-- Restore the fingerprints, states and resolutions 000982 changed. Every
-- touched row first gets a unique placeholder, so restoring cannot collide.
UPDATE exposure_events e SET fingerprint = encode(sha256(convert_to('ct-restore:' || e.id::text, 'UTF8')), 'hex')
FROM easm_ct_rekey_000982 b WHERE e.id = b.id;

UPDATE exposure_events e SET
    fingerprint = b.old_fingerprint,
    state = b.old_state,
    resolved_at = b.old_resolved_at,
    resolution_notes = b.old_resolution_notes,
    updated_at = now()
FROM easm_ct_rekey_000982 b WHERE e.id = b.id;

DROP TABLE IF EXISTS easm_ct_rekey_000982;
