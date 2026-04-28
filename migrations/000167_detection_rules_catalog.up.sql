-- Detection Rules Catalog — Phase A of 3-level findings model.
--
-- Introduces a global, immutable catalog of detection rules
-- (Tenable plugin / Qualys QID / scanner ruleset entry). Every
-- finding gains an FK pointer to the catalog row that produced it.
--
-- This migration is purely additive — no read path changes, no
-- breaking schema removals. Phases B–E (instance + event log
-- separation) build on this foundation. See
-- api/docs/architecture/findings-3level-data-model.md.
--
-- Rollback is safe: the down migration drops the new column and
-- table without disturbing existing finding rows.

BEGIN;

-- =========================================================================
-- 1. Detection rules catalog (global, NOT tenant-scoped)
-- =========================================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id          TEXT PRIMARY KEY,
        -- Composite identity: "<scanner>:<scanner_rule_id>".
        -- Examples:
        --   tenable:156032
        --   trivy:CVE-2021-44228
        --   semgrep:javascript.lang.security.audit.detect-xss
        --   nuclei:exposed-panels/grafana-detect
    scanner          TEXT NOT NULL,
        -- Discriminator. Mirrors values used by `findings.tool_name`
        -- today (trivy / nuclei / semgrep / gitleaks / sarif / etc.).
    scanner_rule_id  TEXT NOT NULL,
        -- Native rule identifier inside the scanner's namespace.
    category         TEXT NOT NULL CHECK (category IN
        ('sast', 'dast', 'sca', 'secret', 'iac', 'container',
         'cspm', 'easm', 'runtime', 'rasp', 'waf', 'siem',
         'misconfig', 'manual', 'unknown')),
        -- Aligned with vulnerability.FindingSource enum so existing
        -- routing rules continue to work after the cutover.
    title            TEXT NOT NULL,
    description      TEXT,
    severity_native  TEXT,
        -- Severity as the scanner reported it. Tenant-context
        -- severity lives on the per-instance row in Phase C.
    cvss_score       NUMERIC(3, 1),
    cvss_vector      TEXT,
    cwe_ids          TEXT[] DEFAULT '{}',
    owasp_ids        TEXT[] DEFAULT '{}',
    cve_ids          TEXT[] DEFAULT '{}',
        -- A single rule can cover multiple CVEs (Log4Shell → 5 CVEs).
        -- Array, not junction table — read pattern is "list CVEs for
        -- this rule", written rarely.
    "references"     JSONB DEFAULT '[]'::jsonb,
    remediation      TEXT,
    fix_versions     TEXT[] DEFAULT '{}',
    metadata         JSONB DEFAULT '{}'::jsonb,
        -- Catalog status — "active" today, "deprecated" once the
        -- scanner removes the rule. Never delete; preserve the FK
        -- target for historical findings.
    status           TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deprecated', 'experimental')),
    source_feed      TEXT,
        -- Where the row came from: 'ingest_autocreate' (created
        -- on-demand at scan time), 'nvd', 'osv', 'ghsa',
        -- 'scanner_native', 'manual_import'. Used by the future
        -- catalog-refresh controller for conflict resolution.
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scanner, scanner_rule_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_scanner_category
    ON detection_rules (scanner, category);

CREATE INDEX IF NOT EXISTS idx_detection_rules_cve_ids_gin
    ON detection_rules USING GIN (cve_ids);

CREATE INDEX IF NOT EXISTS idx_detection_rules_status
    ON detection_rules (status)
    WHERE status != 'active';

COMMENT ON TABLE detection_rules IS
    'Global catalog of detection rules (scanner plugin / QID / template). '
    'See api/docs/architecture/findings-3level-data-model.md.';

-- =========================================================================
-- 2. Add catalog FK on findings (nullable for backward compatibility)
-- =========================================================================
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS detection_rule_id TEXT
    REFERENCES detection_rules(rule_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_detection_rule_id
    ON findings (detection_rule_id)
    WHERE detection_rule_id IS NOT NULL;

COMMENT ON COLUMN findings.detection_rule_id IS
    'FK to detection_rules. Populated by ingest dual-write (Phase A) '
    'and by one-shot backfill below. NULL during Phase A rollout '
    'tolerated; Phase E will tighten to NOT NULL.';

-- =========================================================================
-- 3. Backfill existing findings + populate catalog from observed rules
-- =========================================================================
--
-- Two-step backfill:
--   a) INSERT detection_rules rows from DISTINCT (tool_name, rule_id)
--      pairs already present in findings, marking source_feed as
--      'backfill' so the future refresh controller can over-write them
--      with authoritative metadata when available.
--   b) UPDATE findings.detection_rule_id with the composite key.
--
-- For installs with a small findings table (< 1M rows, typical
-- pre-prod) this runs in seconds. PRODUCTION INSTALLS WITH >1M
-- ROWS must skip step (b) here and run a separate batched
-- backfill controller that processes in chunks of 10K with
-- statement_timeout to avoid long table locks. See backfill
-- runbook in the architecture doc.

INSERT INTO detection_rules (
    rule_id, scanner, scanner_rule_id, category, title,
    severity_native, source_feed
)
SELECT DISTINCT ON (f.tool_name, f.rule_id)
    f.tool_name || ':' || f.rule_id                       AS rule_id,
    f.tool_name                                           AS scanner,
    f.rule_id                                             AS scanner_rule_id,
    CASE f.source::text
        WHEN 'sast'      THEN 'sast'
        WHEN 'dast'      THEN 'dast'
        WHEN 'sca'       THEN 'sca'
        WHEN 'secret'    THEN 'secret'
        WHEN 'iac'       THEN 'iac'
        WHEN 'container' THEN 'container'
        WHEN 'cspm'      THEN 'cspm'
        WHEN 'easm'      THEN 'easm'
        WHEN 'rasp'      THEN 'rasp'
        WHEN 'waf'       THEN 'waf'
        WHEN 'siem'      THEN 'siem'
        WHEN 'manual'    THEN 'manual'
        WHEN 'pentest'   THEN 'manual'
        WHEN 'bug_bounty' THEN 'manual'
        WHEN 'red_team'  THEN 'manual'
        ELSE 'unknown'
    END                                                   AS category,
    COALESCE(NULLIF(f.rule_name, ''), f.message, '(untitled)') AS title,
    f.severity::text                                      AS severity_native,
    'backfill'                                            AS source_feed
FROM findings f
WHERE f.tool_name IS NOT NULL
  AND f.tool_name <> ''
  AND f.rule_id IS NOT NULL
  AND f.rule_id <> ''
ON CONFLICT (rule_id) DO NOTHING;

-- Step (b): populate FK on findings. Skipped for very large tables —
-- the WHERE clause keeps it idempotent: re-running is safe and
-- only touches still-NULL rows.
UPDATE findings f
SET detection_rule_id = f.tool_name || ':' || f.rule_id,
    updated_at        = updated_at  -- preserve mtime; pure FK fill
WHERE f.detection_rule_id IS NULL
  AND f.tool_name IS NOT NULL
  AND f.tool_name <> ''
  AND f.rule_id IS NOT NULL
  AND f.rule_id <> '';

COMMIT;

-- =========================================================================
-- 4. Trigger: auto-populate detection_rules + findings.detection_rule_id
-- =========================================================================
--
-- Phase A keeps the existing ingest-side INSERT statements untouched
-- (the findings repository has 82 columns spread across 3 paths).
-- A BEFORE INSERT trigger ensures every new finding row gets a
-- detection_rule_id FK, and creates the catalog row on first sight.
--
-- Idempotent — `ON CONFLICT DO NOTHING` on the catalog upsert.
-- Skips rows where tool_name or rule_id is empty (e.g. legacy
-- manual findings) so we never produce broken FKs. Phase E will
-- harden these with a NOT NULL constraint after the ingest path
-- is updated to always supply both fields.
--
-- The trigger runs in the same transaction as the INSERT, so a
-- catalog upsert failure aborts the finding insert too — preserving
-- referential integrity without needing a reconciliation job.

CREATE OR REPLACE FUNCTION findings_populate_detection_rule_id()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule_id TEXT;
BEGIN
    -- Only act when the finding has both fields and FK not pre-set.
    -- Pre-set means the application explicitly provided detection_rule_id
    -- (Phase B+ ingest path).
    IF NEW.detection_rule_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.tool_name IS NULL OR NEW.tool_name = '' OR
       NEW.rule_id IS NULL  OR NEW.rule_id  = '' THEN
        RETURN NEW;
    END IF;

    v_rule_id := NEW.tool_name || ':' || NEW.rule_id;

    -- Upsert catalog row. ON CONFLICT preserves authoritative metadata
    -- when a future feed (NVD / OSV) has already populated this rule.
    INSERT INTO detection_rules (
        rule_id, scanner, scanner_rule_id, category, title,
        severity_native, source_feed
    ) VALUES (
        v_rule_id,
        NEW.tool_name,
        NEW.rule_id,
        CASE NEW.source::text
            WHEN 'sast'      THEN 'sast'
            WHEN 'dast'      THEN 'dast'
            WHEN 'sca'       THEN 'sca'
            WHEN 'secret'    THEN 'secret'
            WHEN 'iac'       THEN 'iac'
            WHEN 'container' THEN 'container'
            WHEN 'cspm'      THEN 'cspm'
            WHEN 'easm'      THEN 'easm'
            WHEN 'rasp'      THEN 'rasp'
            WHEN 'waf'       THEN 'waf'
            WHEN 'siem'      THEN 'siem'
            WHEN 'manual'    THEN 'manual'
            WHEN 'pentest'   THEN 'manual'
            WHEN 'bug_bounty' THEN 'manual'
            WHEN 'red_team'  THEN 'manual'
            ELSE 'unknown'
        END,
        COALESCE(NULLIF(NEW.rule_name, ''), NEW.message, '(untitled)'),
        NEW.severity::text,
        'ingest_autocreate'
    )
    ON CONFLICT (rule_id) DO NOTHING;

    NEW.detection_rule_id := v_rule_id;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_findings_populate_detection_rule_id ON findings;
CREATE TRIGGER trg_findings_populate_detection_rule_id
    BEFORE INSERT ON findings
    FOR EACH ROW
    EXECUTE FUNCTION findings_populate_detection_rule_id();

COMMENT ON FUNCTION findings_populate_detection_rule_id() IS
    'Phase A trigger: auto-populate detection_rule_id FK and upsert '
    'detection_rules catalog row. Removed in Phase E once ingest '
    'explicitly writes detection_rule_id.';
