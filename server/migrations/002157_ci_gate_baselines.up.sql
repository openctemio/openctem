-- The CI gate baseline of a repository (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Gate
-- baseline"): the findings open on its default branch when someone with the right role recorded
-- them, or when the repository's first verified default-branch run recorded it (once per
-- repository: a removed baseline keeps its row with cleared_at, so no run records one again).
-- A default-branch run is judged against it, never against what earlier runs saw, so a failing
-- run cannot become the comparison base by being run again.

CREATE TABLE IF NOT EXISTS ci_gate_baselines (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    repository_asset_id UUID NOT NULL,
    source              VARCHAR(20) NOT NULL DEFAULT 'manual',
    branch              VARCHAR(255) NOT NULL DEFAULT '',
    findings_count      INTEGER NOT NULL DEFAULT 0,
    set_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    set_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    cleared_at          TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, repository_asset_id),
    FOREIGN KEY (tenant_id, repository_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_gate_baselines_source CHECK (source IN ('manual', 'first_run'))
);

COMMENT ON TABLE ci_gate_baselines IS 'A repository''s CI gate baseline: when it was recorded, by whom, from which branch.';

CREATE TABLE IF NOT EXISTS ci_gate_baseline_findings (
    tenant_id           UUID NOT NULL,
    repository_asset_id UUID NOT NULL,
    fingerprint         VARCHAR(255) NOT NULL,
    PRIMARY KEY (tenant_id, repository_asset_id, fingerprint),
    FOREIGN KEY (tenant_id, repository_asset_id) REFERENCES ci_gate_baselines (tenant_id, repository_asset_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

COMMENT ON TABLE ci_gate_baseline_findings IS 'The findings (by fingerprint) of a repository''s CI gate baseline; they do not block while it applies.';
