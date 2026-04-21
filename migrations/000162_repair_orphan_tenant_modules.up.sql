-- =============================================================================
-- Migration 000162: Repair tenants whose module state violates the
-- dependency graph shipped in pkg/domain/module/dependency.go.
--
-- Why needed: migration 000161 seeded 20 new modules. The dependency
-- graph went live with commit 59bbffa. Tenants that existed before
-- these commits may have, for example:
--
--     tenant_modules(findings) = disabled
--     (ai_triage row absent → defaults to enabled once 000161 seeds it)
--
-- After 000161 + the graph enforcement, ai_triage would be enabled but
-- its hard dep findings is disabled — violating the invariant, and
-- breaking the next attempt to toggle anything (the validate step
-- rejects the whole batch because of the orphan state).
--
-- This migration walks every tenant_modules row and, for each disabled
-- module, disables every module that HARD-depends on it. The edge list
-- is hard-coded here to match pkg/domain/module/dependency.go — the
-- unit test DetectCycle/ReferencedModulesExist in that package keeps
-- the Go graph honest; a future refactor could generate this SQL from
-- the Go source to prevent drift.
--
-- Rerun-safe: the INSERT uses ON CONFLICT DO UPDATE, and the SELECT
-- only picks rows that need disabling.
--
-- Down migration is a no-op — once a tenant's state is repaired we
-- cannot know which disables were "natural" vs "cascade" without an
-- audit trail; leaving the repair in place is the safe default.
-- =============================================================================

BEGIN;

-- Helper: a temp table holding every (dependent, dep) hard edge from
-- pkg/domain/module/dependency.go. Kept as DATA so the UPDATE below is
-- a simple join, not a 25-branch CASE expression.
CREATE TEMP TABLE _module_hard_edges (dependent TEXT NOT NULL, dep TEXT NOT NULL) ON COMMIT DROP;

INSERT INTO _module_hard_edges (dependent, dep) VALUES
    -- Scoping
    ('attack_surface',     'assets'),
    ('scope_config',       'assets'),
    ('business_services',  'assets'),
    ('ctem_cycles',        'scope_config'),
    ('relationships',      'assets'),
    -- Discovery
    ('credentials',        'assets'),
    ('components',         'assets'),
    ('branches',           'assets'),
    ('vulnerabilities',    'findings'),
    -- Prioritisation
    ('threat_intel',       'findings'),
    ('exposures',          'findings'),
    ('ai_triage',          'findings'),
    ('priority_rules',     'findings'),
    ('risk_analysis',      'findings'),
    ('risk_analysis',      'assets'),
    ('business_impact',    'business_services'),
    ('risk_scoring',       'findings'),
    -- Validation
    ('pentest',            'findings'),
    ('attack_simulation',  'attacker_profiles'),
    ('attack_simulation',  'assets'),
    ('control_testing',    'compensating_controls'),
    ('compensating_controls','findings'),
    -- Mobilisation
    ('remediation',        'findings'),
    ('remediation_tasks',  'remediation'),
    ('workflows',          'findings'),
    ('suppressions',       'findings'),
    -- Insights
    ('executive_summary',  'findings'),
    ('ctem_maturity',      'ctem_cycles'),
    ('mitre_coverage',     'threat_intel'),
    ('sbom_export',        'components'),
    -- Settings
    ('scanner_templates',  'scans'),
    ('template_sources',   'scanner_templates'),
    ('scan_pipelines',     'scans');

-- Step 1 — compute the set of (tenant, dependent_module_id) pairs that
-- SHOULD be disabled given the currently-disabled deps. "enabled" is
-- the default absent an override; a row in tenant_modules with
-- is_enabled=false (or no row at all for the dep but the tenant has
-- disabled it via another edge) flips the dependent to disabled.
--
-- We iterate until fixpoint — if disabling ai_triage cascades to
-- disabling priority_rules (which in the current graph it doesn't,
-- but a future edge might), the loop catches that on the next pass.
-- Postgres doesn't have native loops in plain SQL, so we implement
-- transitive closure with a recursive CTE.
WITH RECURSIVE disabled_per_tenant AS (
    -- Base: every (tenant, module) explicitly disabled today.
    -- Cast to TEXT so the recursive term (which joins against the TEXT
    -- columns of _module_hard_edges) unifies on the same column type.
    -- depth tracks recursion level so we can bound iteration; a cycle
    -- in the edge data (defensive guard — DetectCycle Go test catches
    -- intentional cycles, but a corrupted INSERT could slip through)
    -- would otherwise loop until statement_timeout. 50 levels is far
    -- more than the actual graph depth (~5).
    SELECT tm.tenant_id, tm.module_id::TEXT AS dep, 0 AS depth
      FROM tenant_modules tm
     WHERE tm.is_enabled = false
    UNION
    -- Recursive: every dependent of an already-disabled dep.
    SELECT d.tenant_id, e.dependent::TEXT, d.depth + 1
      FROM disabled_per_tenant d
      JOIN _module_hard_edges e ON e.dep = d.dep
     WHERE d.depth < 50
)
INSERT INTO tenant_modules (tenant_id, module_id, is_enabled, disabled_at, updated_at, created_at)
SELECT d.tenant_id,
       d.dep AS module_id,                    -- the dependent we want to disable
       false AS is_enabled,
       NOW() AS disabled_at,
       NOW() AS updated_at,
       NOW() AS created_at
  FROM disabled_per_tenant d
  JOIN modules m ON m.id = d.dep              -- only disable modules that EXIST in the registry
 WHERE NOT m.is_core                          -- NEVER disable a core module via this repair
   AND NOT EXISTS (                           -- skip entries already disabled
        SELECT 1 FROM tenant_modules x
         WHERE x.tenant_id = d.tenant_id
           AND x.module_id = d.dep
           AND x.is_enabled = false
   )
ON CONFLICT (tenant_id, module_id) DO UPDATE SET
    is_enabled = false,
    disabled_at = NOW(),
    updated_at = NOW();

COMMIT;
