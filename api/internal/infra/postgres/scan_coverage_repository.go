package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanCoverageRepository persists the license-aware coverage rotation cursor
// (RFC-007 Phase 3) and reads scannable candidate assets for a tenant.
//
// All queries are tenant-scoped. The cursor is the asset coverage ledger row
// of capability network_va.connector (docs/rfcs/RFC-093-asset-coverage.md);
// candidate assets are read from `assets` with a LEFT JOIN so
// never-dispatched assets (no ledger row) sort first.
type ScanCoverageRepository struct {
	db *DB
}

// NewScanCoverageRepository creates a ScanCoverageRepository.
func NewScanCoverageRepository(db *DB) *ScanCoverageRepository {
	return &ScanCoverageRepository{db: db}
}

// coverageAssetTypes are the stored asset types a network vulnerability
// scanner (Nessus/Tenable) can target by IP/CIDR/hostname. A subnet is
// (network, subnet), so `network` covers it (RFC-042 §6.3.8). Rows still
// stored under a legacy alias name (`subnet`, `vpc` ...) are included until
// the data normalisation moves them.
var coverageAssetTypes = func() []string {
	types := asset.WithLegacyNames(asset.AssetTypeHost, asset.AssetTypeIPAddress, asset.AssetTypeNetwork)
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = string(t)
	}
	return out
}()

// connectorCapability is the ledger capability of a connector dispatch.
const connectorCapability = coverage.CapabilityNetworkVAConnector

// ListCandidates returns active, scannable assets for a tenant ordered
// oldest-dispatched first (never-dispatched first), with their criticality and
// last-dispatch timestamp. The planner re-sorts, so ordering here is only a
// sensible default + LIMIT bound.
func (r *ScanCoverageRepository) ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]scancoverage.Candidate, error) {
	if limit <= 0 {
		limit = 1000
	}
	const query = `
		SELECT a.id, a.name, a.criticality, c.last_attempt_at, c.last_success_at IS NOT NULL
		FROM assets a
		LEFT JOIN asset_coverage c
		       ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
		      AND c.capability = '` + connectorCapability + `' AND c.vantage = ''
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.status = 'active'
		  AND a.asset_type = ANY($2)
		ORDER BY c.last_attempt_at ASC NULLS FIRST, a.criticality DESC
		LIMIT $3`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(coverageAssetTypes), limit)
	if err != nil {
		return nil, fmt.Errorf("list coverage candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()

	candidates := make([]scancoverage.Candidate, 0, limit)
	for rows.Next() {
		var (
			id, name, criticality string
			lastDispatched        sql.NullTime
			assessed              bool
		)
		if err := rows.Scan(&id, &name, &criticality, &lastDispatched, &assessed); err != nil {
			return nil, fmt.Errorf("scan coverage candidate: %w", err)
		}
		cand := scancoverage.Candidate{
			AssetID:     id,
			Target:      name,
			Criticality: criticality,
			Assessed:    assessed,
		}
		if lastDispatched.Valid {
			t := lastDispatched.Time
			cand.LastScannedAt = &t
		}
		candidates = append(candidates, cand)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate coverage candidates: %w", err)
	}
	return candidates, nil
}

// ActiveIPs returns the IPs the scheduler believes are live on a capped engine
// for this tenant.
//
// Active-IP accounting (Tenable.sc) is not modelled yet — it lands with the
// reclaim-ACK work (Phase 3.5). Today the scheduler only drives unlimited
// engines, which never call this. It returns 0 so a capped engine would compute
// full headroom; callers MUST NOT enable capped-engine coverage until accounting
// exists (the controller filters capped engines out for exactly this reason).
func (r *ScanCoverageRepository) ActiveIPs(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

// CoverageStats returns a point-in-time coverage summary for a tenant
// (RFC-007 Phase 4 observability), computed with conditional aggregation over
// the scannable estate LEFT JOIN the rotation cursor. windowDays defines the
// freshness window. Tenant-scoped.
func (r *ScanCoverageRepository) CoverageStats(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, windowDays int) (*scancoverage.CoverageStats, error) {
	if windowDays <= 0 {
		windowDays = scancoverage.DefaultCoverageWindowDays
	}
	inScope, scopeArgs := sqlTrue, []any(nil)
	if scope != nil {
		inScope, scopeArgs = dataScopeCondAt("a.id", scope, 4)
	}
	//nolint:gosec // G202: inScope is built from fixed SQL and numbered placeholders
	query := `
		WITH scannable AS (
			SELECT a.criticality, c.last_attempt_at AS last_dispatched_at
			FROM assets a
			LEFT JOIN asset_coverage c
			       ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
			      AND c.capability = '` + connectorCapability + `' AND c.vantage = ''
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1
			  AND a.status = 'active'
			  AND a.asset_type = ANY($2)
			  AND ` + inScope + `
		)
		SELECT
			count(*),
			count(*) FILTER (WHERE last_dispatched_at IS NULL),
			count(*) FILTER (WHERE last_dispatched_at >= now() - make_interval(days => $3)),
			count(*) FILTER (WHERE last_dispatched_at IS NOT NULL
			                   AND last_dispatched_at < now() - make_interval(days => $3)),
			count(*) FILTER (WHERE last_dispatched_at IS NULL AND criticality = 'critical'),
			count(*) FILTER (WHERE criticality = 'critical'
			                   AND (last_dispatched_at IS NULL
			                        OR last_dispatched_at < now() - make_interval(days => $3))),
			min(last_dispatched_at)
		FROM scannable`

	stats := &scancoverage.CoverageStats{WindowDays: windowDays}
	var oldest sql.NullTime
	if err := r.db.QueryRowContext(ctx, query, append([]any{tenantID.String(), pq.Array(coverageAssetTypes), windowDays}, scopeArgs...)...).Scan(
		&stats.TotalScannable,
		&stats.NeverScanned,
		&stats.CoveredInWindow,
		&stats.Stale,
		&stats.CriticalNeverScanned,
		&stats.CriticalUncovered,
		&oldest,
	); err != nil {
		return nil, fmt.Errorf("coverage stats: %w", err)
	}
	if oldest.Valid {
		t := oldest.Time
		stats.OldestDispatchedAt = &t
	}
	if stats.TotalScannable > 0 {
		stats.CoveragePercent = float64(stats.CoveredInWindow) / float64(stats.TotalScannable) * 100
	}
	return stats, nil
}

// MarkDispatched advances the rotation cursor for every asset in a dispatched
// batch: it upserts the ledger row of each asset with the dispatch time
// so those assets sort last next cycle, in state queued until the batch
// settles (SettleConnectorBatch). Idempotent per (asset).
func (r *ScanCoverageRepository) MarkDispatched(ctx context.Context, rec scancoverage.DispatchRecord) error {
	if len(rec.AssetIDs) == 0 {
		return nil
	}
	// One statement cannot update one asset twice: a batch naming an asset
	// twice used to fail and leave the whole rotation cursor where it was.
	assetIDs := dedupeLastWins(rec.AssetIDs, func(id string) string { return id })
	const query = `
		INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state,
		                            queued_at, last_attempt_at, last_outcome, updated_at)
		SELECT a.tenant_id, a.id, '` + connectorCapability + `', '', 'queued', now(), now(), 'dispatched', now()
		FROM assets a WHERE a.tenant_id = $2 AND a.id = ANY($1::uuid[])
		ON CONFLICT (tenant_id, asset_id, capability, vantage) DO UPDATE SET
			state           = 'queued',
			queued_at       = EXCLUDED.queued_at,
			last_attempt_at = EXCLUDED.last_attempt_at,
			last_outcome    = EXCLUDED.last_outcome,
			updated_at      = now()`

	if _, err := r.db.ExecContext(ctx, query, pq.Array(assetIDs), rec.TenantID.String()); err != nil {
		return fmt.Errorf("mark dispatched: %w", err)
	}
	return nil
}

// coverageSeen renders each candidate's planned cursor for the claim SQL: the
// RFC 3339 timestamp, or NULL for a never-dispatched asset.
func coverageSeen(batch []scancoverage.Candidate) (ids []string, seen []sql.NullString) {
	ids = make([]string, len(batch))
	seen = make([]sql.NullString, len(batch))
	for i, c := range batch {
		ids[i] = c.AssetID
		if c.LastScannedAt != nil {
			seen[i] = sql.NullString{String: c.LastScannedAt.UTC().Format(time.RFC3339Nano), Valid: true}
		}
	}
	return ids, seen
}

// ClaimBatch claims a planned batch: a never-dispatched asset gets a cursor row
// (INSERT .. ON CONFLICT DO NOTHING), a dispatched one has its cursor moved
// only if it still holds the value the caller planned with. A replica racing
// for the same asset blocks on the row (or the key), re-checks, and loses. It
// returns the asset ids this caller won.
func (r *ScanCoverageRepository) ClaimBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) ([]string, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	ids, seen := coverageSeen(batch)
	const query = `
		WITH want AS (
			SELECT w.asset_id, w.seen
			FROM unnest($2::uuid[], $3::timestamptz[]) AS w(asset_id, seen)
		), ins AS (
			INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, last_attempt_at)
			SELECT a.tenant_id, a.id, '` + connectorCapability + `', '', 'queued', $4
			FROM want w JOIN assets a ON a.tenant_id = $1 AND a.id = w.asset_id
			WHERE w.seen IS NULL
			ON CONFLICT (tenant_id, asset_id, capability, vantage) DO NOTHING
			RETURNING asset_id
		), upd AS (
			UPDATE asset_coverage s
			SET last_attempt_at = $4, state = 'queued', updated_at = now()
			FROM want w
			WHERE s.tenant_id = $1 AND s.asset_id = w.asset_id
			  AND s.capability = '` + connectorCapability + `' AND s.vantage = ''
			  AND w.seen IS NOT NULL AND s.last_attempt_at = w.seen
			RETURNING s.asset_id
		)
		SELECT asset_id::text FROM ins
		UNION ALL
		SELECT asset_id::text FROM upd`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(ids), pq.Array(seen), at)
	if err != nil {
		return nil, fmt.Errorf("claim coverage batch: %w", err)
	}
	defer func() { _ = rows.Close() }()
	claimed := make([]string, 0, len(batch))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan claimed asset: %w", err)
		}
		claimed = append(claimed, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed assets: %w", err)
	}
	return claimed, nil
}

// ReleaseBatch undoes a claim after a failed dispatch: cursors that still hold
// the claim time go back to what the caller planned with (rows the claim
// created are removed). A cursor someone else has since moved is left alone.
func (r *ScanCoverageRepository) ReleaseBatch(ctx context.Context, tenantID shared.ID, batch []scancoverage.Candidate, at time.Time) error {
	if len(batch) == 0 {
		return nil
	}
	ids, seen := coverageSeen(batch)
	const query = `
		WITH want AS (
			SELECT w.asset_id, w.seen
			FROM unnest($2::uuid[], $3::timestamptz[]) AS w(asset_id, seen)
		), del AS (
			DELETE FROM asset_coverage s
			USING want w
			WHERE s.tenant_id = $1 AND s.asset_id = w.asset_id
			  AND s.capability = '` + connectorCapability + `' AND s.vantage = ''
			  AND w.seen IS NULL AND s.last_attempt_at = $4
			RETURNING s.asset_id
		)
		UPDATE asset_coverage s
		SET last_attempt_at = w.seen, state = 'covered', updated_at = now()
		FROM want w
		WHERE s.tenant_id = $1 AND s.asset_id = w.asset_id
		  AND s.capability = '` + connectorCapability + `' AND s.vantage = ''
		  AND w.seen IS NOT NULL AND s.last_attempt_at = $4`
	if _, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(ids), pq.Array(seen), at); err != nil {
		return fmt.Errorf("release coverage claim: %w", err)
	}
	return nil
}

// Compile-time checks: the repository satisfies the scheduler's ports.
var (
	_ scancoverage.CursorStore         = (*ScanCoverageRepository)(nil)
	_ scancoverage.CoverageStatsReader = (*ScanCoverageRepository)(nil)
)

// SettleConnectorBatch settles a finished coverage batch's targets in the
// ledger (research/143 §3.3): assessed → covered (last success now);
// no reply → failed "unreachable"; unfinished → due again (no failure
// counted); failed → failed with the batch's error. Targets are the batch
// command's own (asset names); only this tenant's connector rows change.
func (r *ScanCoverageRepository) SettleConnectorBatch(ctx context.Context, tenantID shared.ID, b scancoverage.BatchSettlement) error {
	// A batch is one command's targets (at most MaxUnfinishedTargets);
	// anything larger is refused rather than allocated.
	for _, list := range [][]string{b.Done, b.Unreachable, b.Unfinished, b.Failed} {
		if len(list) > MaxUnfinishedTargets {
			return fmt.Errorf("%w: a coverage batch settles at most %d targets", shared.ErrValidation, MaxUnfinishedTargets)
		}
	}
	size := len(b.Done) + len(b.Unreachable) + len(b.Unfinished) + len(b.Failed)
	if size > MaxUnfinishedTargets {
		return fmt.Errorf("%w: a coverage batch settles at most %d targets", shared.ErrValidation, MaxUnfinishedTargets)
	}
	targets := make([]string, 0, size)
	kinds := make([]string, 0, size)
	add := func(list []string, kind string) {
		for _, t := range list {
			targets = append(targets, t)
			kinds = append(kinds, kind)
		}
	}
	add(b.Done, "done")
	add(b.Unreachable, "unreachable")
	add(b.Unfinished, "unfinished")
	add(b.Failed, "failed")
	if len(targets) == 0 {
		return nil
	}
	const query = `
		WITH s AS (SELECT * FROM unnest($2::text[], $3::text[]) AS s(target, kind))
		UPDATE asset_coverage c SET
			state           = CASE s.kind WHEN 'done' THEN 'covered' WHEN 'unfinished' THEN 'due' ELSE 'failed' END,
			last_success_at = CASE WHEN s.kind = 'done' THEN now() ELSE c.last_success_at END,
			last_outcome    = CASE s.kind WHEN 'done' THEN 'ok' ELSE s.kind END,
			last_error      = CASE s.kind WHEN 'failed' THEN left($4, 500)
			                              WHEN 'unreachable' THEN 'no reply to the Tenable.sc scan' ELSE '' END,
			fail_streak     = CASE WHEN s.kind IN ('failed', 'unreachable') THEN LEAST(c.fail_streak + 1, 32767) ELSE 0 END,
			queued_at       = NULL,
			updated_at      = now()
		FROM s
		JOIN assets a ON a.tenant_id = $1 AND lower(a.name) = lower(s.target) AND a.deleted_at IS NULL
		WHERE c.tenant_id = $1 AND c.asset_id = a.id
		  AND c.capability = '` + connectorCapability + `' AND c.vantage = ''`
	if _, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(targets), pq.Array(kinds), b.Error); err != nil {
		return fmt.Errorf("settle coverage batch: %w", err)
	}
	return nil
}

// ConnectorCycleProgress counts the tenant's assets eligible for connector
// coverage and those the connector assessed since a cycle started.
func (r *ScanCoverageRepository) ConnectorCycleProgress(ctx context.Context, tenantID shared.ID, since time.Time) (eligible, assessed int, err error) {
	const query = `
		SELECT count(*), count(*) FILTER (WHERE c.last_success_at >= $3)
		FROM assets a
		LEFT JOIN asset_coverage c
		       ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
		      AND c.capability = '` + connectorCapability + `' AND c.vantage = ''
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.status = 'active'
		  AND a.asset_type = ANY($2)`
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), pq.Array(coverageAssetTypes), since).Scan(&eligible, &assessed); err != nil {
		return 0, 0, fmt.Errorf("coverage cycle progress: %w", err)
	}
	return eligible, assessed, nil
}
