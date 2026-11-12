-- Receipt outcomes (research 436): where every finding a producer sent went,
-- beyond the action counts. A map of fixed outcome codes to counts, summed per
-- receipt and per tool row, so received + split always equals created + still
-- detected + reopened + suppressed + failed + skipped + the outcomes.
-- A constant default: no table rewrite, no long lock.
ALTER TABLE ingest_receipts
    ADD COLUMN IF NOT EXISTS outcomes jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE ingest_receipt_tools
    ADD COLUMN IF NOT EXISTS outcomes jsonb NOT NULL DEFAULT '{}'::jsonb;
