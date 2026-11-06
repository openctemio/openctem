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
	// The origin's own ledger row, if any: the 30 day floor, and what a
	// release gives back.
	var (
		last, prevAt sql.NullTime
		prevRun      sql.NullString
		prevGranted  sql.NullInt64
		prevHost     sql.NullString
	)
	err = tx.QueryRowContext(ctx, `SELECT last_dispatch_at, run_id::text, granted, host FROM web_path_discovery_runs
		WHERE tenant_id = $1 AND origin_asset_id = $2`, tenant, assetID).Scan(&last, &prevRun, &prevGranted, &prevHost)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("path discovery: claim ledger: %w", err)
	}
	if last.Valid && time.Since(last.Time) < coverage.PathEvery {
		return 0, coverage.ReasonPathRanRecently, nil
	}
	prevAt = last
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
	var command any
	if !c.CommandID.IsZero() {
		command = c.CommandID.String()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO web_path_discovery_runs (tenant_id, origin_asset_id, host, run_id, granted, last_dispatch_at,
		                                     claim_command_id, prev_dispatch_at, prev_run_id, prev_granted, prev_host)
		VALUES ($1, $2, $3, $4, $5, now(), $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, origin_asset_id) DO UPDATE
		   SET host = EXCLUDED.host, run_id = EXCLUDED.run_id, granted = EXCLUDED.granted, last_dispatch_at = now(),
		       claim_command_id = EXCLUDED.claim_command_id, prev_dispatch_at = EXCLUDED.prev_dispatch_at,
		       prev_run_id = EXCLUDED.prev_run_id, prev_granted = EXCLUDED.prev_granted, prev_host = EXCLUDED.prev_host`,
		tenant, assetID, coverage.Clip(host, 255), run, granted, command,
		prevAt, prevRun, prevGranted, prevHost); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim record: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("path discovery: claim commit: %w", err)
	}
	return granted, "", nil
}

// ReleasePathClaim gives back the origins the command claimed: the row each
// one replaced is restored, or removed when the origin had none. It takes the
// same per-tenant lock as a claim, and a row another dispatch has since
// claimed (a different claim_command_id) is not touched.
func (r *WebPathLedgerRepository) ReleasePathClaim(ctx context.Context, tenantID, commandID shared.ID, origins []string) error {
	if commandID.IsZero() {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("path discovery: release: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	tenant := tenantID.String()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openctem.web_path_discovery:' || $1::text))`, tenant); err != nil {
		return fmt.Errorf("path discovery: release lock: %w", err)
	}
	var names any
	if origins != nil {
		list := make([]string, 0, len(origins))
		for _, o := range origins {
			list = append(list, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o), "/")))
		}
		names = pq.Array(list)
	}
	// An origin filter of NULL is every origin of the command.
	const scope = ` WHERE tenant_id = $1 AND claim_command_id = $2
		  AND ($3::text[] IS NULL OR origin_asset_id IN (
		        SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND ` + originNameSQL + ` = ANY($3::text[])))`
	if _, err := tx.ExecContext(ctx, `UPDATE web_path_discovery_runs
		SET last_dispatch_at = prev_dispatch_at, run_id = prev_run_id, granted = prev_granted, host = prev_host,
		    claim_command_id = NULL, prev_dispatch_at = NULL, prev_run_id = NULL, prev_granted = NULL, prev_host = NULL`+
		scope+` AND prev_dispatch_at IS NOT NULL`, tenant, commandID.String(), names); err != nil {
		return fmt.Errorf("path discovery: release restore: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_path_discovery_runs`+scope+` AND prev_dispatch_at IS NULL`,
		tenant, commandID.String(), names); err != nil {
		return fmt.Errorf("path discovery: release remove: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("path discovery: release commit: %w", err)
	}
	return nil
}

// ReleaseEmptyPathClaim gives back the claims of a job that sent no request,
// on the named origins (exact, normalised names), and only on an origin that
// has not been given back in the last 30 days (release_at). The row it
// replaced is restored; when the origin had none, the row stays with an aged
// last dispatch so release_at survives and the origin counts as never run.
// Same lock as a claim; a claim a later dispatch overwrote is left alone.
func (r *WebPathLedgerRepository) ReleaseEmptyPathClaim(ctx context.Context, tenantID, commandID shared.ID, origins []string) error {
	if commandID.IsZero() || len(origins) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("path discovery: release empty: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	tenant := tenantID.String()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('openctem.web_path_discovery:' || $1::text))`, tenant); err != nil {
		return fmt.Errorf("path discovery: release empty lock: %w", err)
	}
	list := make([]string, 0, len(origins))
	for _, o := range origins {
		list = append(list, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o), "/")))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE web_path_discovery_runs
		SET last_dispatch_at = COALESCE(prev_dispatch_at, now() - interval '31 days'),
		    run_id = prev_run_id, granted = COALESCE(prev_granted, granted), host = COALESCE(prev_host, host),
		    release_at = now(),
		    claim_command_id = NULL, prev_dispatch_at = NULL, prev_run_id = NULL, prev_granted = NULL, prev_host = NULL
		WHERE tenant_id = $1 AND claim_command_id = $2
		  AND (release_at IS NULL OR release_at <= now() - interval '30 days')
		  AND origin_asset_id IN (
		        SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND `+originNameSQL+` = ANY($3::text[]))`,
		tenant, commandID.String(), pq.Array(list)); err != nil {
		return fmt.Errorf("path discovery: release empty: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("path discovery: release empty commit: %w", err)
	}
	return nil
}
