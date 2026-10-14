package postgres

// Asset coverage ledger (docs/rfcs/RFC-093-asset-coverage.md).

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetCoverageRepository reads and writes the coverage ledger. Every query
// is scoped to one tenant.
type AssetCoverageRepository struct {
	db *DB
}

// NewAssetCoverageRepository creates the repository.
func NewAssetCoverageRepository(db *DB) *AssetCoverageRepository {
	return &AssetCoverageRepository{db: db}
}

const coverageRowColumns = `capability, vantage, state, reason, priority, next_due_at, queued_at,
	last_attempt_at, last_success_at, last_outcome, last_error, last_tool, last_run_id,
	fail_streak, change_token, created_at, updated_at`

func scanCoverageRow(sc interface{ Scan(...any) error }, tenantID, assetID shared.ID) (coverage.Row, error) {
	var (
		row                                    coverage.Row
		state                                  string
		nextDue, queued, lastAttempt, lastSucc sql.NullTime
		runID                                  sql.NullString
	)
	err := sc.Scan(&row.Capability, &row.Vantage, &state, &row.Reason, &row.Priority, &nextDue, &queued,
		&lastAttempt, &lastSucc, &row.LastOutcome, &row.LastError, &row.LastTool, &runID,
		&row.FailStreak, &row.ChangeToken, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return row, err
	}
	row.TenantID, row.AssetID, row.State = tenantID, assetID, coverage.State(state)
	row.NextDueAt, row.QueuedAt = coverageTime(nextDue), coverageTime(queued)
	row.LastAttemptAt, row.LastSuccessAt = coverageTime(lastAttempt), coverageTime(lastSucc)
	if runID.Valid {
		if id, err := shared.IDFromString(runID.String); err == nil {
			row.LastRunID = &id
		}
	}
	return row, nil
}

func coverageTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// ListForAsset returns every ledger row of an asset of the tenant.
func (r *AssetCoverageRepository) ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]coverage.Row, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+coverageRowColumns+`
		FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2
		ORDER BY capability, vantage`, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("list asset coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.Row
	for rows.Next() {
		row, err := scanCoverageRow(rows, tenantID, assetID)
		if err != nil {
			return nil, fmt.Errorf("scan asset coverage: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// TenantsWithAssets returns the tenants that have active assets.
func (r *AssetCoverageRepository) TenantsWithAssets(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		WHERE EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = t.id AND a.deleted_at IS NULL AND a.status = 'active')
		ORDER BY t.id`)
	if err != nil {
		return nil, fmt.Errorf("list coverage tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// coveragePredicateSQL is the SQL condition of one rule predicate on the
// asset row "a". Only the closed set of predicates exists; an unknown one is
// false (the rule never applies) so a typo can never widen coverage.
func coveragePredicateSQL(p string) string {
	switch p {
	case coverage.RequiresResolves:
		return `EXISTS (SELECT 1 FROM asset_relationships rr
			WHERE rr.tenant_id = a.tenant_id AND rr.source_asset_id = a.id AND rr.relationship_type = 'resolves_to')`
	case coverage.RequiresWebPort:
		ports := make([]string, len(coverage.WebPorts))
		for i, n := range coverage.WebPorts {
			ports[i] = "'" + strconv.Itoa(n) + "'"
		}
		return `COALESCE(a.properties->>'port', '') IN (` + strings.Join(ports, ", ") + `)`
	case coverage.RequiresScopeEntry:
		return `EXISTS (SELECT 1 FROM scope_targets st
			WHERE st.tenant_id = a.tenant_id AND st.status = 'active'
			  AND (st.expires_at IS NULL OR st.expires_at > now())
			  AND st.target_type IN ('domain', 'subdomain')
			  AND ` + dnsScopeMatch("st.pattern") + `)`
	}
	return "false"
}

// coverageRuleSQL returns the applicability and reason expressions of a rule.
func coverageRuleSQL(rule coverage.Rule) (ok, reason string) {
	if len(rule.Requires) == 0 {
		return "true", "''"
	}
	conds := make([]string, 0, len(rule.Requires))
	var reasonCase strings.Builder
	reasonCase.WriteString("CASE")
	for _, p := range rule.Requires {
		c := "(" + coveragePredicateSQL(p) + ")"
		conds = append(conds, c)
		// p is from the closed predicate set (validated by the registry
		// generator); quote it anyway.
		reasonCase.WriteString(" WHEN NOT " + c + " THEN " + pq.QuoteLiteral(p))
	}
	reasonCase.WriteString(" ELSE '' END")
	return strings.Join(conds, " AND "), reasonCase.String()
}

// Reconcile adds the missing rows of every applicable rule for the tenant's
// active assets and flips rows whose precondition changed. One statement per
// rule; every statement is bound to the tenant.
func (r *AssetCoverageRepository) Reconcile(ctx context.Context, tenantID shared.ID, rules []coverage.Rule) (added, changed int, err error) {
	for _, rule := range rules {
		if !coverage.ValidCapability(rule.Capability) {
			continue
		}
		ok, reason := coverageRuleSQL(rule)
		excluded := coverage.AliasSubTypes(rule.Type)
		if rule.SubType != "" {
			excluded = nil
		}
		// ok and reason are built from the closed predicate set and quoted
		// literals only; every value is a parameter.
		q := `
			WITH cand AS (
				SELECT a.id, (` + ok + `) AS ok, (` + reason + `) AS why
				FROM assets a
				WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.status = 'active'
				  AND a.asset_type = $2
				  AND ($3 = '' OR a.sub_type = $3)
				  AND NOT (COALESCE(a.sub_type, '') = ANY(COALESCE($5::text[], '{}')))
			), ins AS (
				INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, reason, next_due_at)
				SELECT $1, c.id, $4, '', CASE WHEN c.ok THEN 'due' ELSE 'not_applicable' END, c.why, now()
				FROM cand c
				ON CONFLICT (tenant_id, asset_id, capability, vantage) DO NOTHING
				RETURNING 1
			), upd AS (
				UPDATE asset_coverage s
				SET state = CASE WHEN c.ok THEN 'due' ELSE 'not_applicable' END,
				    reason = c.why,
				    next_due_at = CASE WHEN c.ok THEN now() ELSE s.next_due_at END,
				    updated_at = now()
				FROM cand c
				WHERE s.tenant_id = $1 AND s.asset_id = c.id AND s.capability = $4 AND s.vantage = ''
				  AND ((c.ok AND s.state = 'not_applicable') OR
				       (NOT c.ok AND s.state IN ('due', 'failed', 'covered')))
				RETURNING 1
			)
			SELECT (SELECT count(*) FROM ins), (SELECT count(*) FROM upd)`
		var a, c int
		if err := r.db.QueryRowContext(ctx, q, //nolint:gosec // built from a closed set; values are parameters
			tenantID.String(), string(rule.Type), rule.SubType, rule.Capability, pq.Array(excluded),
		).Scan(&a, &c); err != nil {
			return added, changed, fmt.Errorf("reconcile coverage %s/%s %s: %w", rule.Type, rule.SubType, rule.Capability, err)
		}
		added += a
		changed += c
	}
	return added, changed, nil
}

var _ coverage.Repository = (*AssetCoverageRepository)(nil)
