-- expand-contract-ok: widening varchar(16) to varchar(32) is metadata-only (no rewrite, old pods keep working); the new value only adds an allowed outcome
-- A retest of a check that probes several paths can find that the finding's
-- own endpoint no longer matches while another path of the target does:
-- outcome still_exposed_elsewhere, reason matched_elsewhere. Widens the two
-- check constraints; no data changes (instant on a populated table apart
-- from the constraint validation scan). The reason list includes the codes
-- of the edge-block settlement (edge_blocked, access_denied), so the
-- constraint is the same whichever of the two changes ships first.
-- The outcome column was varchar(16); raising a varchar limit rewrites nothing.
ALTER TABLE finding_retests ALTER COLUMN outcome TYPE varchar(32);
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_outcome;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_outcome CHECK (
    outcome IS NULL OR outcome IN ('confirmed_fixed', 'not_reproduced', 'still_vulnerable', 'inconclusive',
        'still_exposed_elsewhere'));
ALTER TABLE finding_retests DROP CONSTRAINT chk_finding_retests_reason_code;
ALTER TABLE finding_retests ADD CONSTRAINT chk_finding_retests_reason_code CHECK (
    reason_code IS NULL OR reason_code IN ('matched', 'not_matched', 'no_endpoint_proof', 'unreachable', 'blocked',
        'auth_changed', 'server_error', 'endpoint_mismatch', 'template_changed', 'no_result', 'error',
        'check_uncalibrated', 'template_not_found', 'excluded_by_policy', 'no_verdict',
        'edge_blocked', 'access_denied', 'matched_elsewhere'));
