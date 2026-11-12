package postgres

// Reads of compliance check states (docs/architecture/compliance-checks.md,
// "Reads"). Every read is pinned to the tenant and, with a scope, to the
// viewer's assets (dataScopeCond on the state's or posture row's asset).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

var _ compliancecheck.Reader = (*ComplianceCheckRepository)(nil)

// maxBenchmarks bounds the benchmarks one read lists.
const maxBenchmarks = 200

// ListBenchmarks returns each benchmark's posture over the viewer's assets
// (or one asset), from the precomputed posture rows: benchmarks with
// failures first.
func (r *ComplianceCheckRepository) ListBenchmarks(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, assetID *shared.ID) ([]compliancecheck.BenchmarkPosture, error) {
	args := []any{tenantID.String()}
	cond, args := dataScopeCond("p.asset_id", scope, args)
	where := "p.tenant_id = $1 AND " + cond
	if assetID != nil {
		args = append(args, assetID.String())
		where += fmt.Sprintf(" AND p.asset_id = $%d", len(args))
	}
	//nolint:gosec // G201: the WHERE is built from fixed parts and placeholders.
	q := fmt.Sprintf(`
		SELECT p.benchmark_key, max(p.benchmark_name), COALESCE(max(p.benchmark_version), ''), COALESCE(max(p.framework), ''),
		       count(*), count(*) FILTER (WHERE p.fail_count > 0),
		       sum(p.pass_count), sum(p.fail_count), sum(p.manual_count), sum(p.not_applicable_count),
		       sum(p.error_count), sum(p.excepted_count), max(p.last_checked_at)
		FROM compliance_posture p
		WHERE %s
		GROUP BY p.benchmark_key
		ORDER BY sum(p.fail_count) DESC, max(p.benchmark_name), p.benchmark_key
		LIMIT %d`, where, maxBenchmarks)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list compliance benchmarks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []compliancecheck.BenchmarkPosture{}
	for rows.Next() {
		var b compliancecheck.BenchmarkPosture
		c := &b.Counts
		if err := rows.Scan(&b.Key, &b.Name, &b.Version, &b.Framework, &b.Assets, &b.FailingAssets,
			&c.Pass, &c.Fail, &c.Manual, &c.NotApplicable, &c.Error, &c.Excepted, &b.LastCheckedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func resultStrings(rs []compliancecheck.Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}

// complianceExceptedSQL: a failed state whose finding is accepted or a
// false positive.
const complianceExceptedSQL = `s.result = 'fail' AND f.status IN ('accepted', 'false_positive')`

// ListControls returns a benchmark's controls over the viewer's assets,
// failed first.
func (r *ComplianceCheckRepository) ListControls(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, benchmarkKey string,
	flt compliancecheck.ControlFilter, page pagination.Pagination) (pagination.Result[compliancecheck.ControlSummary], error) {
	args := []any{tenantID.String(), benchmarkKey}
	cond, args := dataScopeCond("s.asset_id", scope, args)
	where := "s.tenant_id = $1 AND s.benchmark_key = $2 AND " + cond
	if q := strings.TrimSpace(flt.Search); q != "" {
		args = append(args, "%"+escapeLikePattern(compliancecheck.Clip(q, 200))+"%")
		where += fmt.Sprintf(" AND (s.control_id ILIKE $%[1]d OR s.control_name ILIKE $%[1]d)", len(args))
	}
	having := ""
	if len(flt.Results) > 0 {
		args = append(args, pq.Array(resultStrings(flt.Results)))
		having = fmt.Sprintf("HAVING count(*) FILTER (WHERE s.result = ANY($%d::text[])) > 0", len(args))
	}
	args = append(args, page.Limit(), page.Offset())
	//nolint:gosec // G201: the clauses are built from fixed parts and placeholders.
	q := fmt.Sprintf(`
		SELECT s.control_id, COALESCE(max(s.control_name), ''), COALESCE(min(s.compliance_level), 0),
		       count(*) FILTER (WHERE s.result = 'pass'), count(*) FILTER (WHERE s.result = 'fail'),
		       count(*) FILTER (WHERE s.result = 'manual'), count(*) FILTER (WHERE s.result = 'not_applicable'),
		       count(*) FILTER (WHERE s.result = 'error'), count(*) FILTER (WHERE `+complianceExceptedSQL+`),
		       max(s.last_checked_at), count(*) OVER ()
		FROM compliance_check_states s
		LEFT JOIN findings f ON f.id = s.finding_id AND f.tenant_id = s.tenant_id
		WHERE %s
		GROUP BY s.control_id
		%s
		ORDER BY count(*) FILTER (WHERE s.result = 'fail') DESC, count(*) FILTER (WHERE s.result = 'manual') DESC,
		         count(*) FILTER (WHERE s.result = 'error') DESC, s.control_id
		LIMIT $%d OFFSET $%d`, where, having, len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[compliancecheck.ControlSummary]{}, fmt.Errorf("list compliance controls: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []compliancecheck.ControlSummary
	var total int64
	for rows.Next() {
		var c compliancecheck.ControlSummary
		k := &c.Counts
		if err := rows.Scan(&c.ControlID, &c.ControlName, &c.Level, &k.Pass, &k.Fail, &k.Manual, &k.NotApplicable, &k.Error,
			&k.Excepted, &c.LastCheckedAt, &total); err != nil {
			return pagination.Result[compliancecheck.ControlSummary]{}, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[compliancecheck.ControlSummary]{}, err
	}
	return pagination.NewResult(out, total, page), nil
}

// ListControlAssets returns the state of one control on each of the
// viewer's assets, failed first.
func (r *ComplianceCheckRepository) ListControlAssets(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, benchmarkKey, controlID string,
	results []compliancecheck.Result, page pagination.Pagination) (pagination.Result[compliancecheck.ControlAsset], error) {
	args := []any{tenantID.String(), benchmarkKey, controlID}
	cond, args := dataScopeCond("s.asset_id", scope, args)
	where := "s.tenant_id = $1 AND s.benchmark_key = $2 AND s.control_id = $3 AND " + cond
	if len(results) > 0 {
		args = append(args, pq.Array(resultStrings(results)))
		where += fmt.Sprintf(" AND s.result = ANY($%d::text[])", len(args))
	}
	args = append(args, page.Limit(), page.Offset())
	//nolint:gosec // G201: the WHERE is built from fixed parts and placeholders.
	q := fmt.Sprintf(`
		SELECT s.asset_id::text, a.name, a.asset_type, s.result, COALESCE(s.benchmark_version, ''), s.evidence,
		       COALESCE(s.scanner_severity, ''), s.finding_id::text, COALESCE(f.status, ''), s.last_checked_at,
		       s.last_changed_at, count(*) OVER ()
		FROM compliance_check_states s
		JOIN assets a ON a.id = s.asset_id AND a.tenant_id = s.tenant_id
		LEFT JOIN findings f ON f.id = s.finding_id AND f.tenant_id = s.tenant_id
		WHERE %s
		ORDER BY CASE s.result WHEN 'fail' THEN 0 WHEN 'manual' THEN 1 WHEN 'error' THEN 2 WHEN 'not_applicable' THEN 3 ELSE 4 END,
		         a.name, s.asset_id
		LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[compliancecheck.ControlAsset]{}, fmt.Errorf("list compliance control assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []compliancecheck.ControlAsset
	var total int64
	for rows.Next() {
		var (
			a         compliancecheck.ControlAsset
			assetID   string
			result    string
			evidence  []byte
			findingID sql.NullString
		)
		if err := rows.Scan(&assetID, &a.AssetName, &a.AssetType, &result, &a.BenchmarkVersion, &evidence, &a.ScannerSeverity,
			&findingID, &a.FindingStatus, &a.LastCheckedAt, &a.LastChangedAt, &total); err != nil {
			return pagination.Result[compliancecheck.ControlAsset]{}, err
		}
		a.AssetID, _ = shared.IDFromString(assetID)
		a.Result = compliancecheck.Result(result)
		_ = json.Unmarshal(evidence, &a.Evidence)
		if findingID.Valid {
			if id, err := shared.IDFromString(findingID.String); err == nil {
				a.FindingID = &id
			}
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[compliancecheck.ControlAsset]{}, err
	}
	return pagination.NewResult(out, total, page), nil
}

// FindingControlHistory returns the state and history of the control whose
// state links the finding (the newest such state), or nil.
func (r *ComplianceCheckRepository) FindingControlHistory(ctx context.Context, tenantID, findingID shared.ID, limit int) (*compliancecheck.ControlHistory, error) {
	if limit <= 0 || limit > compliancecheck.MaxHistory {
		limit = compliancecheck.MaxHistory
	}
	var (
		h       compliancecheck.ControlHistory
		assetID string
		result  string
		name    sql.NullString
		level   sql.NullInt16
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT s.asset_id::text, s.benchmark_key, s.benchmark_name, s.control_id, s.control_name, s.compliance_level,
		       s.result, s.last_checked_at
		FROM compliance_check_states s
		WHERE s.tenant_id = $1 AND s.finding_id = $2
		ORDER BY s.last_checked_at DESC LIMIT 1`, tenantID.String(), findingID.String()).
		Scan(&assetID, &h.BenchmarkKey, &h.BenchmarkName, &h.ControlID, &name, &level, &result, &h.LastCheckedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("compliance control of a finding: %w", err)
	}
	h.ControlName, h.Level, h.Result = name.String, level.Int16, compliancecheck.Result(result)
	rows, err := r.db.QueryContext(ctx, `
		SELECT result, COALESCE(previous_result, ''), evidence, COALESCE(benchmark_version, ''), COALESCE(tool_name, ''),
		       source, observed_at, recorded_at
		FROM compliance_check_results
		WHERE tenant_id = $1 AND asset_id = $2 AND benchmark_key = $3 AND control_id = $4
		ORDER BY observed_at DESC, recorded_at DESC
		LIMIT $5`, tenantID.String(), assetID, h.BenchmarkKey, h.ControlID, limit)
	if err != nil {
		return nil, fmt.Errorf("compliance control history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	h.Entries = []compliancecheck.HistoryEntry{}
	for rows.Next() {
		var (
			e         compliancecheck.HistoryEntry
			res, prev string
			evidence  []byte
		)
		if err := rows.Scan(&res, &prev, &evidence, &e.BenchmarkVersion, &e.ToolName, &e.Source, &e.ObservedAt, &e.RecordedAt); err != nil {
			return nil, err
		}
		e.Result, e.PreviousResult = compliancecheck.Result(res), compliancecheck.Result(prev)
		_ = json.Unmarshal(evidence, &e.Evidence)
		e.ObservedAt, e.RecordedAt = e.ObservedAt.UTC(), e.RecordedAt.UTC()
		h.Entries = append(h.Entries, e)
	}
	return &h, rows.Err()
}
