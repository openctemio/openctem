-- A quarantined sensor report is marked accepted only once it was applied
-- (docs/rfcs/RFC-122-ingest-receipts.md, "Queue hygiene"; RFC-040 group C).
--
-- Accepting used to mark the item accepted before ingest ran, so an apply
-- that failed left an item accepted and never applied. Now an accept first
-- claims the item (applying_at, the item stays pending): a second accept of
-- the same item meanwhile is refused; a successful apply marks it accepted,
-- a failed one clears the claim so it can be accepted again. A claim older
-- than 15 minutes (a crashed server) no longer blocks.
--
-- Live impact: one nullable column on sensor_result_quarantine (metadata
-- only). No backfill.

ALTER TABLE sensor_result_quarantine
    ADD COLUMN IF NOT EXISTS applying_at timestamptz;

COMMENT ON COLUMN sensor_result_quarantine.applying_at IS
    'Set while an accept applies the item (it stays pending until the apply succeeds); NULL otherwise. A claim older than 15 minutes is ignored.';
