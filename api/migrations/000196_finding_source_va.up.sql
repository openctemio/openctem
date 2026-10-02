-- Add 'va' — network/host vulnerability assessment — as a finding source.
--
-- Nessus, Tenable, Qualys and OpenVAS scan hosts and services for known
-- vulnerabilities. That is a distinct technique from SAST, DAST, SCA or IaC,
-- and the enum had no value for it. The consequence was not that VA findings
-- were labeled loosely — it was that they were labeled *wrongly*: the Nessus
-- importer sets no tool capabilities, so detectFindingSource fell through to
-- its default and stamped every network vulnerability as 'sast'.
--
-- This follows the procedure documented in value_objects.go: migration first,
-- then the constant. The parity tests added in the previous migration enforce
-- that ordering from now on.
--
-- Widening a CHECK is expand-safe. Old pods never produce 'va', so they are
-- unaffected during a rollout; new pods produce a value the new constraint
-- already accepts. Added NOT VALID first so the ALTER takes only a brief lock
-- and does not scan findings while holding it — every existing row trivially
-- satisfies a superset constraint, so the subsequent VALIDATE cannot fail.

-- The constraint is named chk_findings_source (migration 000012), not the
-- Postgres-default findings_source_check. Dropping the wrong name silently
-- leaves the original in place and adds a second one, and a row then has to
-- satisfy both — which is exactly how this migration first failed its own
-- parity test.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source;

ALTER TABLE findings ADD CONSTRAINT chk_findings_source
    CHECK (source IN (
        'sast', 'dast', 'sca', 'secret', 'iac', 'container',
        'cspm', 'easm', 'va',
        'rasp', 'waf', 'siem',
        'manual', 'pentest', 'bug_bounty', 'red_team',
        'external', 'threat_intel', 'vendor',
        'sarif', 'sca_tool', 'api'
    )) NOT VALID;

ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_source;

-- Its own category rather than reusing 'infrastructure'. That category means
-- configuration scanning (IaC, container images); VA is host and network
-- vulnerability scanning, and a security team treats the two as different work
-- with different owners.
INSERT INTO finding_source_categories (code, name, description, icon, color, display_order) VALUES
('vulnerability_assessment', 'Vulnerability Assessment', 'Network and host vulnerability scanning', 'scan-search', 'red', 9)
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    updated_at = NOW();

INSERT INTO finding_sources (code, name, description, icon, color, display_order, category_id) VALUES
('va', 'Vulnerability Assessment', 'Network and host vulnerability scanning (Nessus, Tenable, Qualys, OpenVAS)', 'scan-search', 'red', 21,
    (SELECT id FROM finding_source_categories WHERE code = 'vulnerability_assessment'))
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    category_id = EXCLUDED.category_id,
    updated_at = NOW();

-- Existing rows are left alone. Nessus findings already stored as 'sast' are
-- wrong, but rewriting them would also rewrite genuine Semgrep findings — the
-- two are indistinguishable after the fact, because tool_name is caller
-- controlled and detectFindingSource discarded the distinction at write time.
-- Correcting history needs a per-tenant decision, not a blanket UPDATE here.
