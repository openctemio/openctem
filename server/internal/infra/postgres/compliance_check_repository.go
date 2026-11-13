package postgres

// Compliance check state storage (docs/architecture/compliance-checks.md):
// the latest result per (asset, benchmark, control) in
// compliance_check_states, the first observation and every change of result
// or evidence in compliance_check_results, and the per-asset posture rollup
// refreshed by the dashboard maintainer (dash_dirty_assets reason 32).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// complianceDirtyReason is the dash_dirty_assets bit "compliance check
// states changed".
const complianceDirtyReason = 32

// ComplianceCheckRepository stores compliance check states.
type ComplianceCheckRepository struct {
	db *DB
}

// NewComplianceCheckRepository creates a ComplianceCheckRepository.
func NewComplianceCheckRepository(db *DB) *ComplianceCheckRepository {
	return &ComplianceCheckRepository{db: db}
}

var _ compliancecheck.Recorder = (*ComplianceCheckRepository)(nil)

type checkKey struct {
	asset, benchmark, control string
}

type storedCheck struct {
	id, result, evidenceHash string
	lastChecked              time.Time
	findingID                sql.NullString
}

// checkStateRow is one state written (inserted or updated) by Record.
type checkStateRow struct {
	ID               string          `json:"id"`
	AssetID          string          `json:"asset_id"`
	BenchmarkKey     string          `json:"benchmark_key"`
	BenchmarkName    string          `json:"benchmark_name"`
	BenchmarkVersion *string         `json:"benchmark_version"`
	Framework        *string         `json:"framework"`
	ControlID        string          `json:"control_id"`
	ControlName      *string         `json:"control_name"`
	Level            *int16          `json:"compliance_level"`
	Result           string          `json:"result"`
	ScannerSeverity  *string         `json:"scanner_severity"`
	Evidence         json.RawMessage `json:"evidence"`
	EvidenceHash     string          `json:"evidence_hash"`
	ToolName         *string         `json:"tool_name"`
	FindingID        *string         `json:"finding_id"`
	ObservedAt       time.Time       `json:"observed_at"`
}

// checkHistoryRow is one compliance_check_results row to append.
type checkHistoryRow struct {
	key              checkKey
	StateID          string          `json:"state_id"`
	AssetID          string          `json:"asset_id"`
	Result           string          `json:"result"`
	PreviousResult   *string         `json:"previous_result"`
	Evidence         json.RawMessage `json:"evidence"`
	BenchmarkVersion *string         `json:"benchmark_version"`
	ToolName         *string         `json:"tool_name"`
	FindingID        *string         `json:"finding_id"`
	ObservedAt       time.Time       `json:"observed_at"`
}

func optText(s string, n int) *string {
	s = compliancecheck.Clip(s, n)
	if s == "" {
		return nil
	}
	return &s
}

// Record stores the observations of one tenant: the latest state of each
// control and a history row for the first observation and every change of
// result or evidence. An observation older than the stored state is kept as
// history only (files arrive out of order); the same observation twice
// changes nothing. Assets and findings are read pinned to the tenant: an
// asset of another tenant is left out as invalid, a finding of another
// tenant is never linked.
func (r *ComplianceCheckRepository) Record(ctx context.Context, tenantID shared.ID, source string, obs []compliancecheck.Observation) (compliancecheck.RecordStats, error) {
	var st compliancecheck.RecordStats
	if tenantID.IsZero() {
		return st, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	if source != compliancecheck.SourceIngest && source != compliancecheck.SourceBackfill {
		return st, fmt.Errorf("%w: unknown compliance check source", shared.ErrValidation)
	}
	latest := latestPerControl(obs, &st)
	if len(latest) == 0 {
		return st, nil
	}
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		owned, err := tenantAssets(ctx, tx, tenantID, latest)
		if err != nil {
			return err
		}
		kept := latest[:0]
		for _, o := range latest {
			if owned[o.AssetID.String()] {
				kept = append(kept, o)
			} else {
				st.Invalid++
			}
		}
		if len(kept) == 0 {
			return nil
		}
		findings, err := findingsByFingerprint(ctx, tx, tenantID, kept)
		if err != nil {
			return err
		}
		stored, err := lockStoredChecks(ctx, tx, tenantID, kept)
		if err != nil {
			return err
		}
		states, history := planCheckWrites(kept, stored, findings, &st)
		ids, err := upsertCheckStates(ctx, tx, tenantID, states)
		if err != nil {
			return err
		}
		if err := appendCheckHistory(ctx, tx, tenantID, source, history, ids); err != nil {
			return err
		}
		st.Assets = writtenAssets(states)
		return markComplianceDirty(ctx, tx, tenantID, st.Assets)
	})
	return st, err
}

// latestPerControl drops invalid observations and keeps, per control, the
// latest one, in (asset, benchmark, control) order: the lock order of the
// state rows.
func latestPerControl(obs []compliancecheck.Observation, st *compliancecheck.RecordStats) []compliancecheck.Observation {
	by := make(map[checkKey]compliancecheck.Observation, len(obs))
	for _, o := range obs {
		o.BenchmarkKey = compliancecheck.Clip(o.BenchmarkKey, compliancecheck.MaxBenchmarkKeyLen)
		o.ControlID = compliancecheck.Clip(o.ControlID, compliancecheck.MaxControlIDLen)
		if !o.Valid() {
			st.Invalid++
			continue
		}
		k := checkKey{o.AssetID.String(), o.BenchmarkKey, o.ControlID}
		if prev, ok := by[k]; !ok || o.ObservedAt.After(prev.ObservedAt) {
			by[k] = o
		}
	}
	out := make([]compliancecheck.Observation, 0, len(by))
	for _, o := range by {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.AssetID != b.AssetID {
			return a.AssetID.String() < b.AssetID.String()
		}
		if a.BenchmarkKey != b.BenchmarkKey {
			return a.BenchmarkKey < b.BenchmarkKey
		}
		return a.ControlID < b.ControlID
	})
	return out
}

func tenantAssets(ctx context.Context, tx *sql.Tx, tenantID shared.ID, obs []compliancecheck.Observation) (map[string]bool, error) {
	ids := make([]string, 0, len(obs))
	for _, o := range obs {
		ids = append(ids, o.AssetID.String())
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("compliance checks: read assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// findingsByFingerprint maps "asset|fingerprint" to the tenant's finding.
func findingsByFingerprint(ctx context.Context, tx *sql.Tx, tenantID shared.ID, obs []compliancecheck.Observation) (map[string]string, error) {
	fps := make([]string, 0, len(obs))
	for _, o := range obs {
		if o.Fingerprint != "" {
			fps = append(fps, o.Fingerprint)
		}
	}
	out := map[string]string{}
	if len(fps) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT asset_id::text, fingerprint, id::text FROM findings
		WHERE tenant_id = $1 AND fingerprint = ANY($2::text[]) AND asset_id IS NOT NULL`,
		tenantID.String(), pq.Array(fps))
	if err != nil {
		return nil, fmt.Errorf("compliance checks: read findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var asset, fp, id string
		if err := rows.Scan(&asset, &fp, &id); err != nil {
			return nil, err
		}
		out[asset+"|"+fp] = id
	}
	return out, rows.Err()
}

func lockStoredChecks(ctx context.Context, tx *sql.Tx, tenantID shared.ID, obs []compliancecheck.Observation) (map[checkKey]storedCheck, error) {
	assets := make([]string, len(obs))
	benches := make([]string, len(obs))
	controls := make([]string, len(obs))
	for i, o := range obs {
		assets[i], benches[i], controls[i] = o.AssetID.String(), o.BenchmarkKey, o.ControlID
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id::text, s.asset_id::text, s.benchmark_key, s.control_id, s.result, s.evidence_hash,
		       s.last_checked_at, s.finding_id::text
		FROM compliance_check_states s
		JOIN unnest($2::uuid[], $3::text[], $4::text[]) AS k(asset_id, benchmark_key, control_id)
		  ON s.asset_id = k.asset_id AND s.benchmark_key = k.benchmark_key AND s.control_id = k.control_id
		WHERE s.tenant_id = $1
		ORDER BY s.asset_id, s.benchmark_key, s.control_id
		FOR UPDATE OF s`, tenantID.String(), pq.Array(assets), pq.Array(benches), pq.Array(controls))
	if err != nil {
		return nil, fmt.Errorf("compliance checks: read states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[checkKey]storedCheck{}
	for rows.Next() {
		var k checkKey
		var s storedCheck
		if err := rows.Scan(&s.id, &k.asset, &k.benchmark, &k.control, &s.result, &s.evidenceHash, &s.lastChecked, &s.findingID); err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, rows.Err()
}

// planCheckWrites decides, per observation, the state to write and the
// history row to append.
func planCheckWrites(obs []compliancecheck.Observation, stored map[checkKey]storedCheck, findings map[string]string,
	st *compliancecheck.RecordStats) ([]checkStateRow, []checkHistoryRow) {
	states := make([]checkStateRow, 0, len(obs))
	history := make([]checkHistoryRow, 0, len(obs))
	for _, o := range obs {
		k := checkKey{o.AssetID.String(), o.BenchmarkKey, o.ControlID}
		ev := o.Evidence.Bounded()
		evJSON, _ := json.Marshal(ev)
		hash := ev.Hash()
		var findingID *string
		if id, ok := findings[k.asset+"|"+o.Fingerprint]; ok && o.Fingerprint != "" {
			findingID = &id
		}
		version := optText(o.BenchmarkVersion, compliancecheck.MaxBenchmarkVersionLen)
		tool := optText(o.ToolName, compliancecheck.MaxToolNameLen)
		h := checkHistoryRow{key: k, AssetID: k.asset, Result: string(o.Result), Evidence: evJSON, BenchmarkVersion: version,
			ToolName: tool, FindingID: findingID, ObservedAt: o.ObservedAt.UTC()}
		prev, exists := stored[k]
		switch {
		case !exists:
			st.Created++
			history = append(history, h)
		case o.ObservedAt.Before(prev.lastChecked):
			// Older than the stored state: history only, never the state.
			st.Older++
			h.StateID = prev.id
			history = append(history, h)
			continue
		case o.ObservedAt.Equal(prev.lastChecked) && string(o.Result) == prev.result && hash == prev.evidenceHash:
			// The same observation again (a file imported twice).
			st.Unchanged++
			continue
		case string(o.Result) != prev.result || hash != prev.evidenceHash:
			st.Changed++
			p := prev.result
			h.PreviousResult = &p
			history = append(history, h)
		default:
			st.Unchanged++
		}
		if findingID == nil && prev.findingID.Valid {
			id := prev.findingID.String
			findingID = &id
		}
		var level *int16
		if o.Level.IsKnown() {
			l := int16(o.Level)
			level = &l
		}
		name := compliancecheck.Clip(o.BenchmarkName, compliancecheck.MaxBenchmarkNameLen)
		if name == "" {
			name = o.BenchmarkKey
		}
		states = append(states, checkStateRow{
			ID: shared.NewID().String(), AssetID: k.asset, BenchmarkKey: k.benchmark, BenchmarkName: name,
			BenchmarkVersion: version, Framework: optText(o.Framework, compliancecheck.MaxFrameworkLen),
			ControlID: k.control, ControlName: optText(o.ControlName, compliancecheck.MaxControlNameLen), Level: level,
			Result: string(o.Result), ScannerSeverity: optText(o.ScannerSeverity, 20), Evidence: evJSON, EvidenceHash: hash,
			ToolName: tool, FindingID: findingID, ObservedAt: o.ObservedAt.UTC(),
		})
	}
	return states, history
}

// upsertCheckStates writes the states and returns the stored id per control
// (an id generated here, or the existing row's when it already existed).
func upsertCheckStates(ctx context.Context, tx *sql.Tx, tenantID shared.ID, states []checkStateRow) (map[checkKey]string, error) {
	ids := map[checkKey]string{}
	if len(states) == 0 {
		return ids, nil
	}
	doc, err := json.Marshal(states)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		INSERT INTO compliance_check_states AS s (id, tenant_id, asset_id, benchmark_key, benchmark_name,
			benchmark_version, framework, control_id, control_name, compliance_level, result, scanner_severity,
			evidence, evidence_hash, tool_name, finding_id, first_seen_at, last_checked_at, last_changed_at)
		SELECT i.id, $1, i.asset_id, i.benchmark_key, i.benchmark_name, i.benchmark_version, i.framework,
		       i.control_id, i.control_name, i.compliance_level, i.result, i.scanner_severity, i.evidence,
		       i.evidence_hash, i.tool_name,
		       -- A finding of this tenant only (re-checked here).
		       (SELECT f.id FROM findings f WHERE f.tenant_id = $1 AND f.id = i.finding_id),
		       i.observed_at, i.observed_at, i.observed_at
		FROM jsonb_to_recordset($2::jsonb) AS i(id uuid, asset_id uuid, benchmark_key text, benchmark_name text,
			benchmark_version text, framework text, control_id text, control_name text, compliance_level smallint,
			result text, scanner_severity text, evidence jsonb, evidence_hash text, tool_name text, finding_id uuid,
			observed_at timestamptz)
		ORDER BY i.asset_id, i.benchmark_key, i.control_id
		ON CONFLICT ON CONSTRAINT uq_compliance_check_states_control DO UPDATE SET
			benchmark_name = EXCLUDED.benchmark_name,
			benchmark_version = COALESCE(EXCLUDED.benchmark_version, s.benchmark_version),
			framework = COALESCE(EXCLUDED.framework, s.framework),
			control_name = COALESCE(EXCLUDED.control_name, s.control_name),
			compliance_level = COALESCE(EXCLUDED.compliance_level, s.compliance_level),
			result = EXCLUDED.result,
			scanner_severity = COALESCE(EXCLUDED.scanner_severity, s.scanner_severity),
			evidence = EXCLUDED.evidence,
			evidence_hash = EXCLUDED.evidence_hash,
			tool_name = COALESCE(EXCLUDED.tool_name, s.tool_name),
			finding_id = COALESCE(EXCLUDED.finding_id, s.finding_id),
			last_changed_at = CASE WHEN (s.result, s.evidence_hash) IS DISTINCT FROM (EXCLUDED.result, EXCLUDED.evidence_hash)
				THEN EXCLUDED.last_checked_at ELSE s.last_changed_at END,
			last_checked_at = GREATEST(s.last_checked_at, EXCLUDED.last_checked_at),
			updated_at = now()
		RETURNING s.id::text, s.asset_id::text, s.benchmark_key, s.control_id`, tenantID.String(), string(doc))
	if err != nil {
		return nil, fmt.Errorf("compliance checks: write states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var k checkKey
		if err := rows.Scan(&id, &k.asset, &k.benchmark, &k.control); err != nil {
			return nil, err
		}
		ids[k] = id
	}
	return ids, rows.Err()
}

// appendCheckHistory appends the history rows; a row identical to one
// already kept (same state, time and result) is not repeated.
func appendCheckHistory(ctx context.Context, tx *sql.Tx, tenantID shared.ID, source string, history []checkHistoryRow, ids map[checkKey]string) error {
	rows := make([]checkHistoryRow, 0, len(history))
	for _, h := range history {
		if h.StateID == "" {
			h.StateID = ids[h.key]
		}
		if h.StateID != "" {
			rows = append(rows, h)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	doc, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO compliance_check_results (tenant_id, state_id, asset_id, benchmark_key, control_id, result,
			previous_result, evidence, benchmark_version, tool_name, finding_id, source, observed_at)
		SELECT $1, s.id, s.asset_id, s.benchmark_key, s.control_id, i.result, i.previous_result, i.evidence,
		       i.benchmark_version, i.tool_name,
		       (SELECT f.id FROM findings f WHERE f.tenant_id = $1 AND f.id = i.finding_id), $3, i.observed_at
		FROM jsonb_to_recordset($2::jsonb) AS i(state_id uuid, asset_id uuid, result text, previous_result text,
			evidence jsonb, benchmark_version text, tool_name text, finding_id uuid, observed_at timestamptz)
		JOIN compliance_check_states s ON s.id = i.state_id AND s.tenant_id = $1
		WHERE NOT EXISTS (SELECT 1 FROM compliance_check_results h
		                  WHERE h.tenant_id = $1 AND h.asset_id = s.asset_id AND h.benchmark_key = s.benchmark_key
		                    AND h.control_id = s.control_id AND h.observed_at = i.observed_at AND h.result = i.result)`, tenantID.String(), string(doc), source)
	if err != nil {
		return fmt.Errorf("compliance checks: write history: %w", err)
	}
	return nil
}

func writtenAssets(states []checkStateRow) []shared.ID {
	seen := map[string]bool{}
	var out []shared.ID
	for _, s := range states {
		if seen[s.AssetID] {
			continue
		}
		seen[s.AssetID] = true
		if id, err := shared.IDFromString(s.AssetID); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// markComplianceDirty queues the assets' posture refresh for the dashboard
// maintainer.
func markComplianceDirty(ctx context.Context, tx *sql.Tx, tenantID shared.ID, assets []shared.ID) error {
	if len(assets) == 0 {
		return nil
	}
	ids := make([]string, len(assets))
	for i, a := range assets {
		ids[i] = a.String()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dash_dirty_assets (tenant_id, asset_id, reasons)
		SELECT $1, a, $3 FROM unnest($2::uuid[]) AS a ORDER BY a`, tenantID.String(), pq.Array(ids), complianceDirtyReason); err != nil {
		return fmt.Errorf("compliance checks: queue posture refresh: %w", err)
	}
	return nil
}

// RecomputePosture recomputes the posture rows of the tenant's assets now
// (the maintainer does it for queued assets; the backfill command calls it
// directly).
func (r *ComplianceCheckRepository) RecomputePosture(ctx context.Context, tenantID shared.ID, assets []shared.ID) error {
	for _, a := range assets {
		if _, err := r.db.ExecContext(ctx, `SELECT compliance_posture_recompute($1, $2)`, tenantID.String(), a.String()); err != nil {
			return fmt.Errorf("compliance posture: %w", err)
		}
	}
	return nil
}
