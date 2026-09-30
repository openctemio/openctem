-- expand-contract-ok: rollback of a numeric widening, only run on a deliberate downgrade.
-- The 0-1 → 0-100 rescale is NOT reverted: which rows were fractions is not
-- recorded, and every reader of the previous binary already accepted 0-100
-- (likelihoodScore normalized both scales). Only the column width is restored;
-- a percentile of exactly 100 does not fit numeric(8,6), so it is clamped to
-- the column maximum first rather than failing the rollback.
UPDATE vulnerabilities SET epss_percentile = 99.999999 WHERE epss_percentile > 99.999999;
ALTER TABLE vulnerabilities ALTER COLUMN epss_percentile TYPE numeric(8,6);
