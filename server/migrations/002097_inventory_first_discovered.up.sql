-- Inventory first, scope later (research/124, RFC-054 §15): a discovered
-- asset joins the inventory at once as 'discovered' (passive only unless an
-- active scope entry covers it) instead of waiting outside it as
-- 'needs_review'. Scope entries stay the only authority for active probes.

ALTER TABLE asset_attributions DROP CONSTRAINT chk_asset_attributions_state;
ALTER TABLE asset_attributions
    ADD CONSTRAINT chk_asset_attributions_state
        CHECK (state IN ('confirmed', 'discovered', 'needs_review', 'candidate', 'dependency', 'monitor_only', 'rejected'));

-- One-time backfill, idempotent: automatic needs_review records (no person
-- decided them; children that follow a host included) move into the
-- inventory as discovered. A person's needs_review stays. A tenant that
-- already keeps the review gate (settings.scope.review_before_inventory)
-- keeps its rows. Re-running matches nothing. The join to tenants is on the
-- record's own tenant.
UPDATE asset_attributions aa
SET state = 'discovered', updated_at = now()
FROM tenants t
WHERE t.id = aa.tenant_id
  AND aa.state = 'needs_review'
  AND aa.decided_at IS NULL
  AND COALESCE(t.settings->'scope'->>'review_before_inventory', '') <> 'true';
