-- expand-contract-ok: widening vulnerabilities.epss_percentile numeric(8,6)→numeric(9,6) is non-destructive (a numeric superset, the same change 000194 made to epss_scores); the data repair below only rescales values, old pods read/write the column identically.
--
-- EPSS percentile: one canonical scale, 0-100.
--
-- epss_scores.percentile and findings.epss_percentile were already 0-100 (the
-- EPSS sync multiplies FIRST's 0-1 fraction by 100; findings copy it from
-- epss_scores during priority classification). vulnerabilities.epss_percentile
-- was MIXED: scanner ingest and the vulnerability API stored whatever the
-- producer sent, and FIRST / nuclei / the sdk-go EPSS enricher send a 0-1
-- fraction while the CTIS schema says 0-100. The UI then rendered a 0-100 value
-- as a fraction ("Top -9890.0%" for CVE-2021-44228). The application now
-- normalizes at ingestion (vulnerability.NormalizeEPSSPercentile); this repairs
-- the rows written before that.
--
-- 1. Widen the column so percentile 100 (FIRST's top CVEs report exactly 1.0)
--    fits; numeric(8,6) tops out at 99.999999.
ALTER TABLE vulnerabilities ALTER COLUMN epss_percentile TYPE numeric(9,6);

-- 2. Rescale 0-1 fractions to 0-100.
--
-- How a fraction is told from a 0-100 value in a mixed column:
--   * > 1          : can only be 0-100. Never touched.
--   * (0.01, 1]    : ambiguous by magnitude, so it is CROSS-CHECKED against the
--                    authoritative local copy of the FIRST feed, epss_scores, by
--                    cve_id. The two readings of x are x (0-100) and 100x
--                    (fraction); they are two orders of magnitude apart, so the
--                    comparison is made on a log scale, where the midpoint
--                    between them is 10x. The value is kept as 0-100 only when
--                    epss_scores.percentile < 10x, i.e. the feed agrees the CVE
--                    sits near the very bottom; otherwise it is rescaled. A log
--                    comparison, not a linear one, because stored values can be
--                    months older than the feed: 0.71234 vs a feed of 24.946
--                    is linearly closer to 0.71 but is plainly the fraction
--                    71.234. Examples: 0.99947 vs 99.948 → 99.947; 0.71234 vs
--                    24.946 → 71.234; 0.9 vs 0.9 (a genuine bottom-1% CVE) →
--                    left alone.
--                    Only when the CVE has no epss_scores row does it fall back
--                    to the ingestion rule: a value <= 1 is a fraction.
--   * [0, 0.01]    : left alone. Both readings mean "bottom 1% of CVEs" and
--                    differ by under one percentile point, and leaving this band
--                    untouched is what makes the repair idempotent: every row it
--                    rescales lands above 1, outside the band it selects, so a
--                    second run changes nothing.
UPDATE vulnerabilities v
SET epss_percentile = v.epss_percentile * 100
WHERE v.epss_percentile > 0.01
  AND v.epss_percentile <= 1
  AND NOT EXISTS (
      SELECT 1
      FROM epss_scores es
      WHERE es.cve_id = v.cve_id
        AND es.percentile IS NOT NULL
        AND es.percentile < v.epss_percentile * 10
  );

-- 3. Same repair for findings. Live data is already 0-100 here, but a finding
--    can carry a percentile persisted by an older ingest path, and the rule is
--    identical. findings.epss_percentile is numeric(5,2), which fits 100.00.
UPDATE findings f
SET epss_percentile = f.epss_percentile * 100
WHERE f.epss_percentile > 0.01
  AND f.epss_percentile <= 1
  AND NOT EXISTS (
      SELECT 1
      FROM epss_scores es
      WHERE es.cve_id = f.cve_id
        AND es.percentile IS NOT NULL
        AND es.percentile < f.epss_percentile * 10
  );
