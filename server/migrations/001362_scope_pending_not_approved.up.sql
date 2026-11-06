-- A scope entry created pending approval was stored with approved_at set
-- (the creation time): approved_at means the entry was approved, so a
-- pending or rejected entry has none. An entry that was approved and then
-- widened back to pending already had it cleared. Idempotent.
UPDATE scope_targets
   SET approved_at = NULL
 WHERE status IN ('pending', 'rejected')
   AND approved_at IS NOT NULL;
