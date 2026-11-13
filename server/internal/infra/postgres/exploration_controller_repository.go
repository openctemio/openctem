package postgres

// What the exploration frontier controller reads
// (docs/architecture/exploration.md, "Scoring and dispatch"). Every read is
// bound to one tenant on every table it touches and bounded.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnmatch"
)

// ExplorationControllerRepository implements exploration.ControllerStore.
type ExplorationControllerRepository struct{ db *DB }

var _ exploration.ControllerStore = (*ExplorationControllerRepository)(nil)

// NewExplorationControllerRepository creates the repository.
func NewExplorationControllerRepository(db *DB) *ExplorationControllerRepository {
	return &ExplorationControllerRepository{db: db}
}

func leadIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// Tenants implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) Tenants(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id)
		ORDER BY t.id`)
	if err != nil {
		return nil, fmt.Errorf("list exploration tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Subjects implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) Subjects(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]exploration.LeadSubject, error) {
	out := map[shared.ID]exploration.LeadSubject{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), a.status = 'archived',
		       COALESCE(a.criticality, ''), COALESCE(a.exposure, '') = 'public', COALESCE(a.is_crown_jewel, false),
		       EXISTS (SELECT 1 FROM findings f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id
		               AND f.status = ANY($3::text[]) AND (f.is_in_kev OR f.severity = 'critical'))
		FROM assets a
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND `+liveAssetSQL("a"),
		tenantID.String(), pq.Array(leadIDStrings(ids)), openStatusArray())
	if err != nil {
		return nil, fmt.Errorf("read lead subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s exploration.LeadSubject
		var typ string
		if err := rows.Scan(&s.ID, &s.Name, &typ, &s.SubType, &s.Archived, &s.Value.Criticality,
			&s.Value.Public, &s.Value.CrownJewel, &s.Value.KEVOrCritical); err != nil {
			return nil, err
		}
		s.Type = asset.AssetType(typ)
		out[s.ID] = s
	}
	return out, rows.Err()
}

// Cells implements exploration.ControllerStore. A settled step is a
// verdict; a useful one is proven. Recent counts are over the last
// DemoteAfter verdicts of the cell.
func (r *ExplorationControllerRepository) Cells(ctx context.Context, tenantID shared.ID) (map[string]exploration.CellStats, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH v AS (
			SELECT l.lead_type, l.capability, v.verdict,
			       row_number() OVER (PARTITION BY l.lead_type, l.capability ORDER BY v.created_at DESC) AS rn
			FROM exploration_verdicts v
			JOIN exploration_leads l ON l.tenant_id = v.tenant_id AND l.id = v.lead_id
			WHERE v.tenant_id = $1 AND l.capability IS NOT NULL)
		SELECT lead_type, capability, count(*), count(*) FILTER (WHERE verdict = 'proven'),
		       count(*) FILTER (WHERE rn <= $2), count(*) FILTER (WHERE rn <= $2 AND verdict = 'proven')
		FROM v GROUP BY lead_type, capability`, tenantID.String(), exploration.DemoteAfter)
	if err != nil {
		return nil, fmt.Errorf("read exploration outcomes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]exploration.CellStats{}
	for rows.Next() {
		var lt, capability string
		var c exploration.CellStats
		if err := rows.Scan(&lt, &capability, &c.Tried, &c.Useful, &c.RecentTried, &c.RecentUseful); err != nil {
			return nil, err
		}
		out[exploration.CellKey(lt, capability)] = c
	}
	return out, rows.Err()
}

// ToolMeanMs implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) ToolMeanMs(ctx context.Context, tenantID shared.ID, tools []string) (map[string]float64, error) {
	out := map[string]float64{}
	if len(tools) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT tool, mean_ms FROM tool_duration_stats WHERE tenant_id = $1 AND tool = ANY($2::text[])`,
		tenantID.String(), pq.Array(tools))
	if err != nil {
		return nil, fmt.Errorf("read tool durations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tool string
		var ms float64
		if err := rows.Scan(&tool, &ms); err != nil {
			return nil, err
		}
		out[tool] = ms
	}
	return out, rows.Err()
}

// DispatchesSince implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) DispatchesSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM exploration_links
		WHERE tenant_id = $1 AND rel = 'dispatched_as' AND created_at >= $2`, tenantID.String(), t).Scan(&n); err != nil {
		return 0, fmt.Errorf("count lead dispatches: %w", err)
	}
	return n, nil
}

// Runs implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) Runs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]exploration.RunFacts, error) {
	out := map[shared.ID]exploration.RunFacts{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, status, created_at, started_at, completed_at FROM scan_runs
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID.String(), pq.Array(leadIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("read lead runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id shared.ID
		var f exploration.RunFacts
		var started, completed sql.NullTime
		if err := rows.Scan(&id, &f.Status, &f.CreatedAt, &started, &completed); err != nil {
			return nil, err
		}
		if started.Valid {
			f.StartedAt = &started.Time
		}
		if completed.Valid {
			f.CompletedAt = &completed.Time
		}
		out[id] = f
	}
	return out, rows.Err()
}

// RunFindings implements exploration.ControllerStore: findings on the asset
// whose sighting was last reported by the run (at most 1000).
func (r *ExplorationControllerRepository) RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]exploration.FindingYield, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.created_at >= r.created_at
		FROM findings f
		JOIN scan_runs r ON r.tenant_id = f.tenant_id AND r.id = $3
		WHERE f.tenant_id = $1 AND f.asset_id = $2
		  AND EXISTS (SELECT 1 FROM finding_sightings s
		              WHERE s.tenant_id = f.tenant_id AND s.finding_id = f.id AND s.last_run_id = $3)
		ORDER BY f.id LIMIT 1000`, tenantID.String(), assetID.String(), runID.String())
	if err != nil {
		return nil, fmt.Errorf("read run findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []exploration.FindingYield
	for rows.Next() {
		var y exploration.FindingYield
		if err := rows.Scan(&y.ID, &y.Created); err != nil {
			return nil, err
		}
		out = append(out, y)
	}
	return out, rows.Err()
}

// Liveness implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) Liveness(ctx context.Context, tenantID, assetID shared.ID) (string, *time.Time, error) {
	var state string
	var checked sql.NullTime
	err := r.db.QueryRowContext(ctx, `SELECT state, last_checked_at FROM asset_liveness WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID.String(), assetID.String()).Scan(&state, &checked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read liveness: %w", err)
	}
	if checked.Valid {
		return state, &checked.Time, nil
	}
	return state, nil, nil
}

// MatchState implements exploration.ControllerStore.
func (r *ExplorationControllerRepository) MatchState(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (exploration.MatchState, error) {
	var m exploration.MatchState
	if len(findingIDs) == 0 {
		return m, nil
	}
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE f.status = ANY($3::text[])
		                        AND (COALESCE(f.confidence, 0) >= $4 OR COALESCE(f.last_seen_tool, f.tool_name) <> 'version-match')),
		       count(*) FILTER (WHERE NOT (f.status = ANY($3::text[])))
		FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(leadIDStrings(findingIDs)), openStatusArray(), vulnmatch.LikelyThreshold).Scan(&m.Total, &m.Confirmed, &m.Closed)
	if err != nil {
		return m, fmt.Errorf("read match state: %w", err)
	}
	return m, nil
}
