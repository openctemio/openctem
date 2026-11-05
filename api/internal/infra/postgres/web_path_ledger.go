package postgres

// The path discovery ledger and the origin facts behind its gate
// (docs/architecture/web-discovery.md, table web_path_discovery_runs). Every
// query carries the tenant: another organization's origins, scope entries
// and dispatches are never read.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WebPathLedgerRepository implements coverage.PathLedger.
type WebPathLedgerRepository struct{ db *DB }

// NewWebPathLedgerRepository returns the repository.
func NewWebPathLedgerRepository(db *DB) *WebPathLedgerRepository {
	return &WebPathLedgerRepository{db: db}
}

var _ coverage.PathLedger = (*WebPathLedgerRepository)(nil)

// originNameSQL is the normalised name of a web service asset.
const originNameSQL = `lower(rtrim(a.name, '/'))`

// pathOriginFactsSQL is the facts query: the live web services named by the
// origins, with the three coverage predicates the planner uses and the last
// dispatch of the ledger. Inventory counts as changed only against the later
// of the capability's last coverage success and the ledger's last dispatch,
// so a run of a workflow step and a run of the planner see each other.
var pathOriginFactsSQL = `
	SELECT DISTINCT ON (` + originNameSQL + `) a.name, a.id,
	       ` + coveragePredicateSQL(coverage.RequiresOriginScopeEntry) + `,
	       EXISTS (SELECT 1 FROM web_endpoints e
	         WHERE e.tenant_id = a.tenant_id AND e.origin_asset_id = a.id AND e.state = 'active'
	           AND e.sources <> '{guess}'
	           AND e.first_seen_at > COALESCE(GREATEST(
	             (SELECT c.last_success_at FROM asset_coverage c
	               WHERE c.tenant_id = a.tenant_id AND c.asset_id = a.id AND c.vantage = ''
	                 AND c.capability = '` + coverage.CapabilityEnumerateWebPaths + `'),
	             (SELECT l.last_dispatch_at FROM web_path_discovery_runs l
	               WHERE l.tenant_id = a.tenant_id AND l.origin_asset_id = a.id)), '-infinity'::timestamptz)),
	       ` + coveragePredicateSQL(coverage.RequiresEdgeClear) + `,
	       (SELECT l.last_dispatch_at FROM web_path_discovery_runs l
	         WHERE l.tenant_id = a.tenant_id AND l.origin_asset_id = a.id)
	FROM assets a
	WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status = 'active'
	  AND a.asset_type = 'service' AND a.sub_type = 'http'
	  AND ` + originNameSQL + ` = ANY($2::text[])
	ORDER BY ` + originNameSQL + `, a.id`

// PathOriginFacts returns the facts of the tenant's live web services named
// by origins (keyed by the normalised origin).
func (r *WebPathLedgerRepository) PathOriginFacts(ctx context.Context, tenantID shared.ID, origins []string) (map[string]coverage.PathOriginFacts, error) {
	out := map[string]coverage.PathOriginFacts{}
	if len(origins) == 0 {
		return out, nil
	}
	names := make([]string, 0, len(origins))
	for _, o := range origins {
		names = append(names, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o), "/")))
	}
	rows, err := r.db.QueryContext(ctx, pathOriginFactsSQL, tenantID.String(), pq.Array(names))
	if err != nil {
		return nil, fmt.Errorf("path discovery: origin facts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			name, id string
			f        coverage.PathOriginFacts
			last     sql.NullTime
		)
		if err := rows.Scan(&name, &id, &f.ScopeEntry, &f.InventoryChanged, &f.EdgeClear, &last); err != nil {
			return nil, fmt.Errorf("path discovery: scan origin facts: %w", err)
		}
		origin, host, ok := coverage.PathOrigin(name)
		if !ok {
			continue
		}
		if f.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		f.Host = host
		if last.Valid {
			f.LastDispatch = last.Time
		}
		out[origin] = f
	}
	return out, rows.Err()
}

// PathRequestsGrantedSince sums the request caps granted to the tenant since t.
func (r *WebPathLedgerRepository) PathRequestsGrantedSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(sum(granted), 0) FROM web_path_discovery_runs
		WHERE tenant_id = $1 AND last_dispatch_at >= $2`, tenantID.String(), t).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("path discovery: granted requests: %w", err)
	}
	return n, nil
}

// ClaimPathOrigin records a dispatch on one origin, atomically per tenant
// (an advisory lock serializes the claims, so concurrent callers cannot spend
// the daily budget twice or both dispatch the same origin).
func (r *WebPathLedgerRepository) ClaimPathOrigin(ctx context.Context, c coverage.PathClaim) (int, string, error) {
	origin, host, ok := coverage.PathOrigin(c.Origin)
	if !ok {
		return 0, coverage.ReasonNotAnOrigin, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", fmt.Errorf("path discovery: claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	tenant := c.TenantID.String()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openctem.web_path_discovery:' || $1::text))`, tenant); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim lock: %w", err)
	}
	var assetID string
	err = tx.QueryRowContext(ctx, `SELECT a.id FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status = 'active'
		  AND a.asset_type = 'service' AND a.sub_type = 'http' AND `+originNameSQL+` = $2
		ORDER BY a.id LIMIT 1`, tenant, origin).Scan(&assetID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, coverage.ReasonNotAnOrigin, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("path discovery: claim origin: %w", err)
	}
	// The origin's own ledger row, if any: the 30 day floor.
	var last sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT last_dispatch_at FROM web_path_discovery_runs
		WHERE tenant_id = $1 AND origin_asset_id = $2`, tenant, assetID).Scan(&last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("path discovery: claim ledger: %w", err)
	}
	if last.Valid && time.Since(last.Time) < coverage.PathEvery {
		return 0, coverage.ReasonPathRanRecently, nil
	}
	granted := c.Requested
	var spentDay int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(sum(granted), 0) FROM web_path_discovery_runs
		WHERE tenant_id = $1 AND last_dispatch_at >= now() - interval '24 hours' AND origin_asset_id <> $2`,
		tenant, assetID).Scan(&spentDay); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim daily: %w", err)
	}
	if left := c.Daily - spentDay; left < granted {
		granted = left
	}
	if granted < coverage.MinPathGrant {
		return 0, coverage.ReasonDailyBudgetSpent, nil
	}
	if c.RunID != nil && c.PerHost > 0 {
		var spentHost int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(sum(granted), 0) FROM web_path_discovery_runs
			WHERE tenant_id = $1 AND host = $2 AND run_id = $3 AND origin_asset_id <> $4`,
			tenant, host, c.RunID.String(), assetID).Scan(&spentHost); err != nil {
			return 0, "", fmt.Errorf("path discovery: claim host: %w", err)
		}
		if left := c.PerHost - spentHost; left < granted {
			granted = left
		}
		if granted < coverage.MinPathGrant {
			return 0, coverage.ReasonHostBudgetSpent, nil
		}
	}
	var run any
	if c.RunID != nil {
		run = c.RunID.String()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO web_path_discovery_runs (tenant_id, origin_asset_id, host, run_id, granted, last_dispatch_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (tenant_id, origin_asset_id) DO UPDATE
		   SET host = EXCLUDED.host, run_id = EXCLUDED.run_id, granted = EXCLUDED.granted, last_dispatch_at = now()`,
		tenant, assetID, coverage.Clip(host, 255), run, granted); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim record: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim commit: %w", err)
	}
	return granted, "", nil
}
