package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanCoverageRepository persists the license-aware coverage rotation cursor
// (RFC-007 Phase 3) and reads scannable candidate assets for a tenant.
//
// All queries are tenant-scoped. The cursor lives in scan_coverage_state
// (migration 000176); candidate assets are read from `assets` with a LEFT JOIN
// so never-dispatched assets (no cursor row) sort first.
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

// ListCandidates returns active, scannable assets for a tenant ordered
// oldest-dispatched first (never-dispatched first), with their criticality and
// last-dispatch timestamp. The planner re-sorts, so ordering here is only a
// sensible default + LIMIT bound.
func (r *ScanCoverageRepository) ListCandidates(ctx context.Context, tenantID shared.ID, limit int) ([]scancoverage.Candidate, error) {
	if limit <= 0 {
		limit = 1000
	}
	const query = `
		SELECT a.id, a.name, a.criticality, c.last_dispatched_at
		FROM assets a
		LEFT JOIN scan_coverage_state c
		       ON c.asset_id = a.id AND c.tenant_id = a.tenant_id
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.status = 'active'
		  AND a.asset_type = ANY($2)
		ORDER BY c.last_dispatched_at ASC NULLS FIRST, a.criticality DESC
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
		)
		if err := rows.Scan(&id, &name, &criticality, &lastDispatched); err != nil {
			return nil, fmt.Errorf("scan coverage candidate: %w", err)
		}
		cand := scancoverage.Candidate{
			AssetID:     id,
			Target:      name,
			Criticality: criticality,
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
func (r *ScanCoverageRepository) CoverageStats(ctx context.Context, tenantID shared.ID, windowDays int) (*scancoverage.CoverageStats, error) {
	if windowDays <= 0 {
		windowDays = scancoverage.DefaultCoverageWindowDays
	}
	const query = `
		WITH scannable AS (
			SELECT a.criticality, c.last_dispatched_at
			FROM assets a
			LEFT JOIN scan_coverage_state c
			       ON c.asset_id = a.id AND c.tenant_id = a.tenant_id
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1
			  AND a.status = 'active'
			  AND a.asset_type = ANY($2)
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
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), pq.Array(coverageAssetTypes), windowDays).Scan(
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
// batch: it upserts scan_coverage_state with the dispatch time, session, and
// command so those assets sort last next cycle. Idempotent per (asset).
func (r *ScanCoverageRepository) MarkDispatched(ctx context.Context, rec scancoverage.DispatchRecord) error {
	if len(rec.AssetIDs) == 0 {
		return nil
	}
	// One statement cannot update one asset twice: a batch naming an asset
	// twice used to fail and leave the whole rotation cursor where it was.
	assetIDs := dedupeLastWins(rec.AssetIDs, func(id string) string { return id })
	const query = `
		INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at, last_session_id, last_command_id)
		SELECT unnest($1::uuid[]), $2, now(), $3, $4
		ON CONFLICT (asset_id) DO UPDATE SET
			last_dispatched_at = EXCLUDED.last_dispatched_at,
			last_session_id    = EXCLUDED.last_session_id,
			last_command_id    = EXCLUDED.last_command_id,
			tenant_id          = EXCLUDED.tenant_id,
			updated_at         = now()`

	var cmdID any
	if !rec.CommandID.IsZero() {
		cmdID = rec.CommandID.String()
	}
	var sessionID any
	if rec.SessionID != "" {
		sessionID = rec.SessionID
	}

	if _, err := r.db.ExecContext(ctx, query,
		pq.Array(assetIDs), rec.TenantID.String(), sessionID, cmdID,
	); err != nil {
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
			INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at)
			SELECT w.asset_id, $1, $4 FROM want w WHERE w.seen IS NULL
			ON CONFLICT (asset_id) DO NOTHING
			RETURNING asset_id
		), upd AS (
			UPDATE scan_coverage_state s
			SET last_dispatched_at = $4, updated_at = now()
			FROM want w
			WHERE s.asset_id = w.asset_id AND s.tenant_id = $1
			  AND w.seen IS NOT NULL AND s.last_dispatched_at = w.seen
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
			DELETE FROM scan_coverage_state s
			USING want w
			WHERE s.asset_id = w.asset_id AND s.tenant_id = $1
			  AND w.seen IS NULL AND s.last_dispatched_at = $4
			RETURNING s.asset_id
		)
		UPDATE scan_coverage_state s
		SET last_dispatched_at = w.seen, updated_at = now()
		FROM want w
		WHERE s.asset_id = w.asset_id AND s.tenant_id = $1
		  AND w.seen IS NOT NULL AND s.last_dispatched_at = $4`
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
