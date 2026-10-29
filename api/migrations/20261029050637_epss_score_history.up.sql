-- EPSS score history (api/docs/architecture/vulnerability-page.md, "EPSS
-- trend"): one point per CVE per feed day, so the vulnerabilities list and
-- the vulnerability page can show how a CVE's exploit probability moved.
--
-- Filled by the EPSS sync, in the same transaction as epss_scores, only for
-- CVEs that at least one finding carries (bounds the table to what any
-- organization can see; the full feed is ~300k CVEs a day). Points older than
-- 30 days are deleted by the same sync.
--
-- Global reference data like epss_scores (no tenant column). Because a row
-- exists only for CVEs some organization has, the history is never served by
-- CVE id alone: it is read only inside the scoped vulnerability reads, for
-- CVEs the caller already has a finding of (no cross-tenant oracle).
--
-- Live impact: a new empty table; filled on the next EPSS sync.

CREATE TABLE IF NOT EXISTS epss_score_history (
    cve_id     varchar(30)  NOT NULL,
    score_date date         NOT NULL,
    epss_score numeric(8,6) NOT NULL,
    percentile numeric(9,6),
    PRIMARY KEY (cve_id, score_date)
);

-- The retention delete scans by day.
CREATE INDEX IF NOT EXISTS idx_epss_score_history_date ON epss_score_history (score_date);

COMMENT ON TABLE epss_score_history IS
    'Daily EPSS points (30 days) for CVEs that findings carry; read only inside scoped vulnerability reads';
