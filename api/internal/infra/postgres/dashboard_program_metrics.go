package postgres

// CTEM program metrics — the ctem.org program KPIs that can be computed from
// data the platform already stores. The precise definitions live on the
// app.ProgramMetrics / app.DurationMetric / app.OwnerAcceptanceMetric types
// (internal/app/module/dashboard.go); the SQL below implements exactly those.
//
// Every query is tenant-scoped on EVERY table it touches (not only the driving
// one), and every aggregate returns NULL — surfaced as a nil pointer, rendered
// "—" — when there is no qualifying sample. Nothing here COALESCEs an empty
// sample to 0 or 100.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// programMetricsMaxDays bounds the window so a hostile ?days= can't turn the
// queries into full-history scans.
const programMetricsMaxDays = 365

// GetProgramMetrics computes the CTEM program metrics for a tenant over the
// last `days` days.
func (r *DashboardRepository) GetProgramMetrics(ctx context.Context, tenantID shared.ID, days int) (*module.ProgramMetrics, error) {
	if days <= 0 || days > programMetricsMaxDays {
		days = 90
	}
	m := &module.ProgramMetrics{PeriodDays: days}

	var err error
	if m.MTTDInternetFacing, err = r.mttdInternetFacing(ctx, tenantID, days); err != nil {
		return nil, err
	}
	if m.MTTRValidated, err = r.mttrValidated(ctx, tenantID, days); err != nil {
		return nil, err
	}
	if m.OwnerAcceptance, err = r.ownerAcceptance(ctx, tenantID, days); err != nil {
		return nil, err
	}
	return m, nil
}

// mttdInternetFacing: first_seen → earliest "known internet-facing / exposed"
// signal, for assets first seen in the window that are internet-facing now.
//
// Plan: the driving set is one tenant's recently-seen internet-facing assets
// (idx_assets_tenant_status); each stop signal is a per-asset MIN over an
// index that leads with asset_id (idx_asset_state_history_asset_time,
// idx_exposure_events_asset, idx_findings_tenant_asset_status). `detected` is
// MATERIALIZED so the four stop-signal lookups run once per asset — inlined,
// Postgres re-evaluated them for every reference to detected_at.
const mttdInternetFacingQuery = `
	WITH fresh AS (
		SELECT a.id, a.first_seen,
			CASE WHEN a.exposure = 'public' THEN a.exposure_changed_at END AS classified_at
		FROM assets a
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
			AND ($3::bool OR NOT a.program_only)
			AND a.status <> 'archived'
			AND (a.exposure = 'public' OR a.is_internet_accessible = true)
			AND a.first_seen >= NOW() - make_interval(days => $2::int)
	),
	detected AS MATERIALIZED (
		SELECT f.first_seen,
			LEAST(
				f.classified_at,
				(SELECT MIN(h.changed_at) FROM asset_state_history h
					WHERE h.asset_id = f.id AND h.tenant_id = $1
						AND h.change_type IN ('exposure_changed', 'internet_exposure_changed')
						AND h.new_value IN ('public', 'true')),
				(SELECT MIN(e.first_seen_at) FROM exposure_events e
					WHERE e.asset_id = f.id AND e.tenant_id = $1),
				(SELECT MIN(fi.first_detected_at) FROM findings fi
					WHERE fi.tenant_id = $1 AND fi.asset_id = f.id AND NOT fi.branch_only)
			) AS detected_at
		FROM fresh f
	),
	timed AS (
		SELECT CASE WHEN detected_at IS NULL THEN NULL
			ELSE GREATEST(EXTRACT(EPOCH FROM (detected_at - first_seen)), 0) / 3600.0
			END AS hours
		FROM detected
	)
	SELECT
		AVG(hours)::float8,
		(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hours))::float8,
		COUNT(hours),
		COUNT(*) FILTER (WHERE hours IS NULL)
	FROM timed
`

func (r *DashboardRepository) mttdInternetFacing(ctx context.Context, tenantID shared.ID, days int) (module.DurationMetric, error) {
	var (
		mean, median sql.NullFloat64
		out          module.DurationMetric
	)
	if err := r.db.QueryRowContext(ctx, mttdInternetFacingQuery, tenantID.String(), days, shared.ProgramAssetsIncluded(ctx)).
		Scan(&mean, &median, &out.SampleSize, &out.Unmeasured); err != nil {
		return out, fmt.Errorf("program metrics mttd: %w", err)
	}
	out.MeanHours = nullFloatPtr(mean)
	out.MedianHours = nullFloatPtr(median)
	return out, nil
}

// mttrValidated: first reproducing validation → resolution, for validated
// findings resolved in the window.
//
// Plan: validation_evidence is aggregated per finding under
// idx_validation_evidence_finding (tenant_id, finding_id, created_at), then
// joined to findings by primary key.
const mttrValidatedQuery = `
	WITH validated AS (
		SELECT ve.finding_id, MIN(ve.created_at) AS validated_at
		FROM validation_evidence ve
		WHERE ve.tenant_id = $1 AND ve.outcome = 'detected'
		GROUP BY ve.finding_id
	),
	timed AS (
		SELECT EXTRACT(EPOCH FROM (f.resolved_at - v.validated_at)) / 3600.0 AS hours
		FROM validated v
		JOIN findings f ON f.id = v.finding_id AND f.tenant_id = $1 AND NOT f.branch_only AND ($3::bool OR NOT EXISTS (SELECT 1 FROM assets pa WHERE pa.tenant_id = $1 AND pa.id = f.asset_id AND pa.program_only))
		WHERE f.status = 'resolved'
			AND f.resolved_at IS NOT NULL
			AND f.resolved_at >= NOW() - make_interval(days => $2::int)
			AND f.resolved_at >= v.validated_at
	)
	SELECT
		AVG(hours)::float8,
		(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hours))::float8,
		COUNT(*)
	FROM timed
`

func (r *DashboardRepository) mttrValidated(ctx context.Context, tenantID shared.ID, days int) (module.DurationMetric, error) {
	var (
		mean, median sql.NullFloat64
		out          module.DurationMetric
	)
	if err := r.db.QueryRowContext(ctx, mttrValidatedQuery, tenantID.String(), days, shared.ProgramAssetsIncluded(ctx)).
		Scan(&mean, &median, &out.SampleSize); err != nil {
		return out, fmt.Errorf("program metrics mttr validated: %w", err)
	}
	out.MeanHours = nullFloatPtr(mean)
	out.MedianHours = nullFloatPtr(median)
	return out, nil
}

// ownerAcceptance classifies each assignment made in the window as accepted /
// missed / pending / excluded (see app.OwnerAcceptanceMetric).
//
// The assignee is read from changes->>'assignee_id' (written by
// activity.Service when a finding is assigned); rows without a well-formed id
// (pre-2026 assignments stored '{}') are skipped, not guessed.
//
// Plan: the driving set comes from idx_finding_activities_tenant_created; the
// per-assignment lookups (next hand-off, owner action) are correlated on
// idx_finding_activities_tenant_finding. `judged` is MATERIALIZED because the
// final SELECT reads it through several FILTERed aggregates: inlined, Postgres
// re-ran the correlated lookups once per aggregate (4x the index probes).
const ownerAcceptanceQuery = `
	WITH asg AS (
		SELECT fa.id, fa.finding_id, fa.created_at AS assigned_at,
			(fa.changes->>'assignee_id')::uuid AS assignee_id,
			f.sla_deadline, f.resolved_at
		FROM finding_activities fa
		JOIN findings f ON f.id = fa.finding_id AND f.tenant_id = $1 AND NOT f.branch_only AND ($3::bool OR NOT EXISTS (SELECT 1 FROM assets pa WHERE pa.tenant_id = $1 AND pa.id = f.asset_id AND pa.program_only))
		WHERE fa.tenant_id = $1
			AND fa.activity_type = 'assigned'
			AND fa.created_at >= NOW() - make_interval(days => $2::int)
			AND fa.changes->>'assignee_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
	),
	relieved AS (
		-- When the assignee stopped being responsible before the SLA deadline:
		-- the next assign/unassign on the finding, or its resolution.
		SELECT a.*,
			LEAST(
				(SELECT MIN(n.created_at) FROM finding_activities n
					WHERE n.tenant_id = $1 AND n.finding_id = a.finding_id
						AND n.activity_type IN ('assigned', 'unassigned')
						AND n.created_at > a.assigned_at),
				CASE WHEN a.resolved_at >= a.assigned_at THEN a.resolved_at END
			) AS relieved_at
		FROM asg a
	),
	judged AS MATERIALIZED (
		SELECT r.*,
			EXISTS (
				SELECT 1 FROM finding_activities x
				WHERE x.tenant_id = $1 AND x.finding_id = r.finding_id
					AND x.actor_type = 'user' AND x.actor_id = r.assignee_id
					AND x.activity_type IN (
						'status_changed', 'triage_updated', 'severity_changed',
						'comment_added', 'remediation_updated', 'resolved', 'verified',
						'false_positive_marked', 'duplicate_marked', 'approval_requested')
					AND x.created_at >= r.assigned_at
					AND x.created_at <= LEAST(r.sla_deadline, COALESCE(r.relieved_at, r.sla_deadline))
			) AS acted
		FROM relieved r
		WHERE r.sla_deadline IS NOT NULL AND r.sla_deadline >= r.assigned_at
	)
	SELECT
		COUNT(*) FILTER (WHERE acted),
		COUNT(*) FILTER (WHERE NOT acted AND sla_deadline < NOW()
			AND (relieved_at IS NULL OR relieved_at >= sla_deadline)),
		COUNT(*) FILTER (WHERE NOT acted AND sla_deadline >= NOW()
			AND (relieved_at IS NULL OR relieved_at >= sla_deadline)),
		(SELECT COUNT(*) FROM asg) - COUNT(*) FILTER (WHERE acted
			OR relieved_at IS NULL OR relieved_at >= sla_deadline)
	FROM judged
`

func (r *DashboardRepository) ownerAcceptance(ctx context.Context, tenantID shared.ID, days int) (module.OwnerAcceptanceMetric, error) {
	var out module.OwnerAcceptanceMetric
	if err := r.db.QueryRowContext(ctx, ownerAcceptanceQuery, tenantID.String(), days, shared.ProgramAssetsIncluded(ctx)).
		Scan(&out.Accepted, &out.Missed, &out.Pending, &out.Excluded); err != nil {
		return out, fmt.Errorf("program metrics owner acceptance: %w", err)
	}
	out.RatePct = acceptanceRate(out.Accepted, out.Missed)
	return out, nil
}

// acceptanceRate is Accepted / (Accepted + Missed) × 100, or nil when no
// assignment has been decided yet — an undecided sample is "not measured",
// not 0% and not 100%.
func acceptanceRate(accepted, missed int) *float64 {
	decided := accepted + missed
	if decided <= 0 {
		return nil
	}
	pct := float64(accepted) / float64(decided) * 100
	return &pct
}

func nullFloatPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}
