// Package compliancechecks is the compliance-checks command: it moves the
// compliance findings stored before compliance check state existed to the
// new model (docs/architecture/compliance-checks.md, "Existing findings").
//
// For every open compliance finding of a tenant it
//
//   - records the state of its control on its asset (source backfill), so the
//     posture and the history start from what is stored;
//   - re-classifies a failure or a warning: the compliance severity from the
//     benchmark level and the asset (vulnerability.ComplianceSeverity), the
//     class from that severity (vulnerability.ClassifyCompliance), and the
//     benchmark level column; an analyst's severity override and a manual
//     class override stand;
//   - closes a finding that is no failure (a passed, not applicable or
//     errored check): resolved, closure reason reclassified_check_state
//     (never counted as fixed), with a timeline entry and an audit log entry
//     per finding. Nothing is deleted.
//
// Closed findings are never touched (forward only). The same functions as
// the write path decide; there is no SQL copy of the rules.
//
// A dry run (the default) opens a read-only connection and prints aggregates
// only, per tenant: findings per result, severity and class moves, closes,
// controls to record, and per benchmark. No finding id or content is
// printed. -apply needs -undo <file>: the file is created (never
// overwritten) and every changed row's previous values are written to it
// before the page that changes them commits. Pages are keyset pages, one
// transaction each; a row changed since it was read is left alone; a rerun
// changes nothing.
//
//	DATABASE_URL  postgres connection string; when unset it is built from the
//	              server's DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME and
//	              DB_SSLMODE, so it runs as-is inside the API container
//
// Usage:
//
//	compliance-checks                           dry run, every tenant
//	compliance-checks -tenant <id>              one tenant
//	compliance-checks -apply -undo <file>       make the changes
//	compliance-checks -json                     the report as JSON
//
// Exit status: 0 success, 1 the run failed, 2 usage or connection error.
package compliancechecks

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DefaultBatchSize is the keyset page size.
const DefaultBatchSize = 2000

// actorName names the command on the timeline and in the audit log.
const actorName = "system: compliance-checks"

// maxBenchmarksReported bounds the per-benchmark rows of a tenant report.
const maxBenchmarksReported = 50

var errUndoRequired = errors.New("-apply needs -undo <file>: the previous values are written there first")

// Options select what a run does.
type Options struct {
	Tenant    *shared.ID // nil: every tenant
	Apply     bool
	BatchSize int
	// UndoPath is the undo file an apply writes first (required with Apply;
	// never overwritten).
	UndoPath string
	// RunID names the run in the audit log (generated when empty).
	RunID string
}

// BenchmarkReport is one benchmark's open compliance findings of a tenant.
type BenchmarkReport struct {
	Key      string         `json:"key"`
	Findings int            `json:"findings"`
	ByResult map[string]int `json:"by_result"`
	// Assets is the distinct assets with an open finding of the benchmark.
	Assets int `json:"assets"`
}

// TenantReport is one tenant's aggregates. It holds counts only.
type TenantReport struct {
	TenantID string `json:"tenant_id"`
	// Open is the open compliance findings considered; Closed the closed
	// ones, never touched.
	Open   int `json:"open"`
	Closed int `json:"closed"`
	// ByResult counts the open findings per compliance result ("" = none).
	ByResult map[string]int `json:"by_result"`
	// Controls is the distinct (asset, benchmark, control) states to record.
	Controls int `json:"controls"`
	// NoControl: open findings without a benchmark or control (no state;
	// still re-classified or closed by their result).
	NoControl int `json:"no_control"`
	// Reclassify: open failures and warnings.
	Reclassified      int            `json:"reclassified"`
	SeverityBefore    map[string]int `json:"severity_before"`
	SeverityAfter     map[string]int `json:"severity_after"`
	SeverityMoves     map[string]int `json:"severity_moves"` // "high>medium"
	ClassMoves        map[string]int `json:"class_moves"`    // "P2>P3"
	LevelSet          int            `json:"level_set"`
	KeptOverride      int            `json:"kept_override"`
	KeptClassOverride int            `json:"kept_class_override"`
	// Closes: open findings whose result is no failure.
	ToClose map[string]int `json:"to_close"` // per result
	// With -apply.
	StatesRecorded int                         `json:"states_recorded"`
	Applied        int                         `json:"applied"`
	ClosedApplied  int                         `json:"closed_applied"`
	Benchmarks     []BenchmarkReport           `json:"benchmarks"`
	benchmarks     map[string]*BenchmarkReport `json:"-"`
	benchAssets    map[string]map[string]bool  `json:"-"`
}

// Report is what a run found and, with Apply, did.
type Report struct {
	Apply   bool           `json:"apply"`
	RunID   string         `json:"run_id,omitempty"`
	Tenants []TenantReport `json:"tenants"`
}

// Main runs the command with os.Args (see cmd/server/tools.go for why it
// parses its flags on a fresh flag set).
func Main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	tenantFlag := flag.String("tenant", "", "tenant id (default: every tenant)")
	apply := flag.Bool("apply", false, "make the changes (default: a dry run)")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	batch := flag.Int("batch", DefaultBatchSize, "rows per page")
	undoPath := flag.String("undo", "", "with -apply: the undo file to create (previous values), never overwritten")
	timeout := flag.Duration("timeout", 2*time.Hour, "overall time limit")
	flag.Parse()

	opts := Options{Apply: *apply, BatchSize: *batch, UndoPath: *undoPath}
	if *tenantFlag != "" {
		id, err := shared.IDFromString(*tenantFlag)
		if err != nil {
			fail(2, "-tenant: not an id")
		}
		opts.Tenant = &id
	}
	if opts.Apply && opts.UndoPath == "" {
		fail(2, errUndoRequired.Error())
	}
	dbURL := databaseURL()
	if dbURL == "" {
		fail(2, "DATABASE_URL (or DB_HOST/DB_*) must be set in the environment")
	}
	if !opts.Apply {
		dbURL = readOnlyURL(dbURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fail(2, "open database: "+err.Error())
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		fail(2, "connect: "+err.Error())
	}
	rep, err := Run(ctx, db, opts)
	if err != nil {
		fail(1, err.Error())
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	fmt.Print(Render(rep))
}

// Run moves the open compliance findings of the selected tenants (a dry run
// unless Apply).
func Run(ctx context.Context, db *sql.DB, opts Options) (*Report, error) {
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}
	rep := &Report{Apply: opts.Apply}
	var undo *csv.Writer
	if opts.Apply {
		if opts.UndoPath == "" {
			return nil, errUndoRequired
		}
		f, w, err := openUndo(opts.UndoPath)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		undo = w
		if opts.RunID == "" {
			opts.RunID = shared.NewID().String()
		}
		rep.RunID = opts.RunID
	}
	tenants, err := listTenants(ctx, db, opts.Tenant)
	if err != nil {
		return nil, err
	}
	for _, tid := range tenants {
		tr, err := runTenant(ctx, db, tid, opts, undo)
		if err != nil {
			return rep, fmt.Errorf("tenant %s: %w", tid, err)
		}
		rep.Tenants = append(rep.Tenants, *tr)
	}
	return rep, nil
}

func listTenants(ctx context.Context, db *sql.DB, only *shared.ID) ([]string, error) {
	if only != nil {
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, only.String()).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("no tenant %s", only.String())
		}
		return []string{only.String()}, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id::text FROM findings WHERE finding_type = 'compliance' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// row is one open compliance finding as read.
type row struct {
	id, assetID, fingerprint, status, severity, class string
	classOverride, severityOverride                   bool
	result, framework, controlID, controlName         string
	title, ruleID, tool                               string
	level                                             vulnerability.ComplianceLevel
	observedAt                                        time.Time
	extra                                             map[string]string
	critical, production                              bool
}

// plan is what the run does to one finding.
type plan struct {
	r                  row
	obs                *compliancecheck.Observation
	result             compliancecheck.Result
	close              bool
	newSeverity        string
	newClass           string
	newLevel           *int16
	severityOrClassNew bool
}

const pageSQL = `
	SELECT f.id::text, COALESCE(f.asset_id::text, ''), f.fingerprint, f.status, f.severity, COALESCE(f.priority_class, ''),
	       COALESCE(f.priority_class_override, false), f.severity_overridden_at IS NOT NULL,
	       COALESCE(f.compliance_result, ''), COALESCE(f.compliance_framework, ''), COALESCE(f.compliance_control_id, ''),
	       COALESCE(f.compliance_control_name, ''), COALESCE(f.title, ''), COALESCE(f.rule_id, ''),
	       COALESCE(f.last_seen_tool, f.tool_name, ''), COALESCE(f.compliance_level, 0),
	       COALESCE(f.last_seen_at, f.created_at), COALESCE(f.source_extra, '{}'::jsonb)::text,
	       COALESCE(a.is_crown_jewel, false) OR COALESCE(a.criticality = 'critical', false),
	       COALESCE(a.environment = 'production', false)
	FROM findings f
	LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
	WHERE f.tenant_id = $1 AND f.finding_type = 'compliance' AND is_open_finding_status(f.status) AND f.id > $2::uuid
	ORDER BY f.id
	LIMIT $3`

func runTenant(ctx context.Context, db *sql.DB, tid string, opts Options, undo *csv.Writer) (*TenantReport, error) {
	tr := &TenantReport{TenantID: tid, ByResult: map[string]int{}, SeverityBefore: map[string]int{}, SeverityAfter: map[string]int{},
		SeverityMoves: map[string]int{}, ClassMoves: map[string]int{}, ToClose: map[string]int{},
		benchmarks: map[string]*BenchmarkReport{}, benchAssets: map[string]map[string]bool{}}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'compliance'
		AND NOT is_open_finding_status(status)`, tid).Scan(&tr.Closed); err != nil {
		return nil, err
	}
	tenantID, err := shared.IDFromString(tid)
	if err != nil {
		return nil, err
	}
	recorder := postgres.NewComplianceCheckRepository(&postgres.DB{DB: db})
	controls := map[string]bool{}
	after := "00000000-0000-0000-0000-000000000000"
	for {
		rows, last, err := readPage(ctx, db, tid, after, opts.BatchSize)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		after = last
		plans := make([]plan, 0, len(rows))
		var obs []compliancecheck.Observation
		for _, r := range rows {
			p := planFor(r)
			tally(tr, p, controls)
			plans = append(plans, p)
			if p.obs != nil {
				obs = append(obs, *p.obs)
			}
		}
		if opts.Apply {
			// States first (idempotent; each a history row), then the
			// finding changes of the page in one transaction.
			st, err := recorder.Record(ctx, tenantID, compliancecheck.SourceBackfill, obs)
			if err != nil {
				return nil, err
			}
			tr.StatesRecorded += st.Created + st.Changed
			n, closed, err := applyPage(ctx, db, tid, opts.RunID, plans, undo)
			if err != nil {
				return nil, err
			}
			tr.Applied += n
			tr.ClosedApplied += closed
		}
		if len(rows) < opts.BatchSize {
			break
		}
	}
	tr.Controls = len(controls)
	tr.Benchmarks = sortedBenchmarks(tr)
	if opts.Apply && (tr.Applied > 0 || tr.StatesRecorded > 0) {
		if err := auditRun(ctx, db, tid, opts.RunID, tr); err != nil {
			return nil, err
		}
	}
	return tr, nil
}

func readPage(ctx context.Context, db *sql.DB, tid, after string, limit int) ([]row, string, error) {
	rs, err := db.QueryContext(ctx, pageSQL, tid, after, limit)
	if err != nil {
		return nil, "", fmt.Errorf("read compliance findings: %w", err)
	}
	defer func() { _ = rs.Close() }()
	var out []row
	last := after
	for rs.Next() {
		var r row
		var level int16
		var extra string
		if err := rs.Scan(&r.id, &r.assetID, &r.fingerprint, &r.status, &r.severity, &r.class, &r.classOverride, &r.severityOverride,
			&r.result, &r.framework, &r.controlID, &r.controlName, &r.title, &r.ruleID, &r.tool, &level, &r.observedAt, &extra,
			&r.critical, &r.production); err != nil {
			return nil, "", err
		}
		r.level = vulnerability.ComplianceLevel(level)
		r.extra = map[string]string{}
		_ = json.Unmarshal([]byte(extra), &r.extra)
		out = append(out, r)
		last = r.id
	}
	return out, last, rs.Err()
}

// resultOf is the stored result of a finding; an error the old ingest
// folded into not_applicable is read back from the scanner's own word.
func resultOf(r row) (compliancecheck.Result, bool) {
	switch strings.ToLower(r.result) {
	case "pass":
		return compliancecheck.ResultPass, true
	case "fail":
		return compliancecheck.ResultFail, true
	case "manual":
		return compliancecheck.ResultManual, true
	case "error":
		return compliancecheck.ResultError, true
	case "not_applicable":
		return compliancecheck.ResultOf("not_applicable", "", r.extra["compliance-result"])
	}
	return "", false
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// planFor decides what happens to one open finding, with the write path's
// functions.
func planFor(r row) plan {
	p := plan{r: r}
	res, ok := resultOf(r)
	if !ok {
		// No result: a compliance finding of a producer that sent no kind.
		// It is treated as a failure (it was reported as a finding).
		res = compliancecheck.ResultFail
	}
	p.result = res
	level := r.level
	if !level.IsKnown() {
		level = vulnerability.ParseComplianceLevel(firstOf(r.extra, "compliance-benchmark-profile", "benchmark_profile", "profile", "level"))
	}
	if aid, err := shared.IDFromString(r.assetID); err == nil {
		name := firstOf(r.extra, "compliance-benchmark-name", "benchmark_name", "benchmark")
		if name == "" {
			name = firstOf(map[string]string{"f": r.framework, "t": r.tool}, "f", "t")
		}
		control := r.controlID
		if control == "" {
			control = r.ruleID
		}
		ctrlName := r.controlName
		if ctrlName == "" {
			ctrlName = r.title
		}
		o := compliancecheck.Observation{AssetID: aid, Fingerprint: r.fingerprint, BenchmarkKey: compliancecheck.BenchmarkKey(name),
			BenchmarkName: name, BenchmarkVersion: firstOf(r.extra, "compliance-benchmark-version", "benchmark_version"),
			Framework: r.framework, ControlID: control, ControlName: ctrlName, Level: level, Result: res,
			ScannerSeverity: r.severity, ToolName: r.tool, ObservedAt: r.observedAt.UTC(),
			Evidence: compliancecheck.Evidence{Expected: r.extra["compliance-policy-value"], Message: r.extra["compliance-error"],
				AuditFile: r.extra["compliance-audit-file"]}}
		if o.Valid() {
			p.obs = &o
		}
	}
	if !res.OpensFinding() {
		p.close = true
		return p
	}
	if level.IsKnown() && level != r.level {
		l := int16(level)
		p.newLevel = &l
	}
	p.newSeverity, p.newClass = r.severity, r.class
	if !r.severityOverride {
		sev, _ := vulnerability.ComplianceSeverity(vulnerability.ComplianceSeverityInput{Result: string(res), Level: level,
			Critical: r.critical, Production: r.production})
		p.newSeverity = string(sev)
	}
	if !r.classOverride {
		p.newClass = string(vulnerability.ClassifyCompliance(vulnerability.PriorityContext{Compliance: true,
			Severity: vulnerability.Severity(p.newSeverity)}).Class)
	}
	p.severityOrClassNew = p.newSeverity != r.severity || p.newClass != r.class
	return p
}

func tally(tr *TenantReport, p plan, controls map[string]bool) {
	r := p.r
	tr.Open++
	tr.ByResult[string(p.result)]++
	if p.obs != nil {
		controls[r.assetID+"|"+p.obs.BenchmarkKey+"|"+p.obs.ControlID] = true
		b := tr.benchmarks[p.obs.BenchmarkKey]
		if b == nil {
			b = &BenchmarkReport{Key: p.obs.BenchmarkKey, ByResult: map[string]int{}}
			tr.benchmarks[p.obs.BenchmarkKey] = b
			tr.benchAssets[p.obs.BenchmarkKey] = map[string]bool{}
		}
		b.Findings++
		b.ByResult[string(p.result)]++
		tr.benchAssets[p.obs.BenchmarkKey][r.assetID] = true
	} else {
		tr.NoControl++
	}
	if p.close {
		tr.ToClose[string(p.result)]++
		return
	}
	tr.SeverityBefore[r.severity]++
	tr.SeverityAfter[p.newSeverity]++
	if r.severityOverride {
		tr.KeptOverride++
	}
	if r.classOverride {
		tr.KeptClassOverride++
	}
	if p.newLevel != nil {
		tr.LevelSet++
	}
	if p.severityOrClassNew || p.newLevel != nil {
		tr.Reclassified++
	}
	if p.newSeverity != r.severity {
		tr.SeverityMoves[r.severity+">"+p.newSeverity]++
	}
	if p.newClass != r.class {
		tr.ClassMoves[orNone(r.class)+">"+orNone(p.newClass)]++
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func sortedBenchmarks(tr *TenantReport) []BenchmarkReport {
	out := make([]BenchmarkReport, 0, len(tr.benchmarks))
	for k, b := range tr.benchmarks {
		b.Assets = len(tr.benchAssets[k])
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > maxBenchmarksReported {
		out = out[:maxBenchmarksReported]
	}
	return out
}

// applyPage writes the page's changes in one transaction, after their
// previous values are in the undo file. A row changed since it was read
// (status, severity or class) is left alone.
func applyPage(ctx context.Context, db *sql.DB, tid, runID string, plans []plan, undo *csv.Writer) (int, int, error) {
	if undo == nil {
		return 0, 0, errUndoRequired
	}
	var changes []plan
	for _, p := range plans {
		if p.close || p.severityOrClassNew || p.newLevel != nil {
			changes = append(changes, p)
		}
	}
	if len(changes) == 0 {
		return 0, 0, nil
	}
	for _, p := range changes {
		action, newStatus := "reclassify", p.r.status
		if p.close {
			action, newStatus = "close", string(vulnerability.FindingStatusResolved)
		}
		lvl := ""
		if p.r.level.IsKnown() {
			lvl = fmt.Sprint(int16(p.r.level))
		}
		if err := undo.Write([]string{tid, p.r.id, action, p.r.status, p.r.severity, p.r.class, lvl, newStatus, p.newSeverity, p.newClass}); err != nil {
			return 0, 0, fmt.Errorf("write undo file: %w", err)
		}
	}
	undo.Flush()
	if err := undo.Error(); err != nil {
		return 0, 0, fmt.Errorf("write undo file: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	reclassified, err := applyReclassify(ctx, tx, tid, changes)
	if err != nil {
		return 0, 0, err
	}
	closed, err := applyCloses(ctx, tx, tid, runID, changes)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return reclassified + closed, closed, nil
}

func applyReclassify(ctx context.Context, tx *sql.Tx, tid string, changes []plan) (int, error) {
	var ids, oldSev, oldClass, newSev, newClass []string
	var levels []sql.NullInt64
	for _, p := range changes {
		if p.close {
			continue
		}
		ids, oldSev, oldClass = append(ids, p.r.id), append(oldSev, p.r.severity), append(oldClass, p.r.class)
		newSev, newClass = append(newSev, p.newSeverity), append(newClass, p.newClass)
		if p.newLevel != nil {
			levels = append(levels, sql.NullInt64{Int64: int64(*p.newLevel), Valid: true})
		} else {
			levels = append(levels, sql.NullInt64{})
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	lv := make([]any, len(levels))
	for i, l := range levels {
		if l.Valid {
			lv[i] = l.Int64
		}
	}
	rows, err := tx.QueryContext(ctx, `
		WITH v AS (
			SELECT * FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::smallint[])
				AS v(id, old_sev, old_class, new_sev, new_class, lvl)
		), upd AS (
			UPDATE findings f SET severity = v.new_sev, priority_class = NULLIF(v.new_class, ''),
				priority_class_reason = CASE WHEN v.new_class IS DISTINCT FROM v.old_class
					THEN 'Compliance check: priority from the benchmark level and the asset, never the scanner''s severity'
					ELSE f.priority_class_reason END,
				compliance_level = COALESCE(v.lvl, f.compliance_level), updated_at = NOW()
			FROM v
			WHERE f.tenant_id = $1 AND f.id = v.id AND f.finding_type = 'compliance' AND is_open_finding_status(f.status)
			  AND f.severity = v.old_sev AND COALESCE(f.priority_class, '') = v.old_class
			RETURNING f.id, v.old_sev, v.new_sev, v.old_class, v.new_class
		), act AS (
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			SELECT $1, u.id, 'severity_changed', 'system', $8,
			       jsonb_build_object('reason', 'compliance_policy', 'old_severity', u.old_sev, 'severity', u.new_sev,
			                          'old_priority_class', NULLIF(u.old_class, ''), 'priority_class', NULLIF(u.new_class, '')),
			       'auto', 'Compliance check re-classified from its benchmark level and asset'
			FROM upd u WHERE u.old_sev <> u.new_sev OR u.old_class <> u.new_class
		)
		SELECT id::text FROM upd`, tid, pq.Array(ids), pq.Array(oldSev), pq.Array(oldClass), pq.Array(newSev), pq.Array(newClass),
		pq.Array(lv), actorName)
	if err != nil {
		return 0, fmt.Errorf("re-classify compliance findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}

// applyCloses resolves the open findings whose result is no failure, with
// the timeline entry (the status transition) and an audit entry per finding.
func applyCloses(ctx context.Context, tx *sql.Tx, tid, runID string, changes []plan) (int, error) {
	var ids, statuses, results []string
	for _, p := range changes {
		if p.close {
			ids, statuses, results = append(ids, p.r.id), append(statuses, p.r.status), append(results, string(p.result))
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tr, err := json.Marshal(vulnerability.StatusTransition{ActivityType: "status_changed", Source: "auto",
		Reason: string(vulnerability.ClosureReasonReclassifiedCheckState), ActorType: "system", ActorName: actorName,
		Message: "A compliance result that was no failure was moved to its control's check state"})
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.transition', $1, true)`, string(tr)); err != nil {
		return 0, fmt.Errorf("set finding transition: %w", err)
	}
	var n int
	err = tx.QueryRowContext(ctx, `
		WITH v AS (
			SELECT * FROM unnest($2::uuid[], $3::text[], $4::text[]) AS v(id, old_status, result)
		), upd AS (
			UPDATE findings f SET status = 'resolved', closure_reason = 'reclassified_check_state', verification = 'none',
				resolution = 'compliance_' || v.result, resolved_at = NOW(), updated_at = NOW()
			FROM v
			WHERE f.tenant_id = $1 AND f.id = v.id AND f.finding_type = 'compliance' AND f.status = v.old_status
			  AND is_open_finding_status(f.status)
			RETURNING f.id, v.old_status, v.result
		), audit AS (
			INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			SELECT gen_random_uuid(), $1, 'finding.status_changed', 'finding', u.id::text, 'success', 'low',
			       'A compliance result that was no failure was moved to its control''s check state',
			       jsonb_build_object('actor', $5::text, 'run_id', $6::text, 'old_status', u.old_status, 'status', 'resolved',
			                          'closure_reason', 'reclassified_check_state', 'compliance_result', u.result), NOW()
			FROM upd u
			ORDER BY u.id
		)
		SELECT count(*) FROM upd`, tid, pq.Array(ids), pq.Array(statuses), pq.Array(results), actorName, runID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("close compliance results: %w", err)
	}
	return n, nil
}

// auditRun records one audit entry per tenant and run: the counts and the
// run id.
func auditRun(ctx context.Context, db *sql.DB, tid, runID string, tr *TenantReport) error {
	meta, err := json.Marshal(map[string]any{
		"command": "compliance-checks", "run_id": runID, "states_recorded": tr.StatesRecorded,
		"reclassified": tr.Applied - tr.ClosedApplied, "closed": tr.ClosedApplied, "severity_moves": tr.SeverityMoves,
		"class_moves": tr.ClassMoves,
	})
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
		VALUES (gen_random_uuid(), $1, 'findings.reclassified', 'finding', NULL, 'success', 'medium', $2, $3, NOW())`,
		tid, "Compliance findings moved to compliance check state by the compliance-checks command", string(meta))
	if err != nil {
		return fmt.Errorf("audit the run: %w", err)
	}
	return nil
}

func openUndo(path string) (*os.File, *csv.Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen path
	if err != nil {
		return nil, nil, fmt.Errorf("create undo file (never overwritten): %w", err)
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"tenant_id", "finding_id", "action", "status", "severity", "priority_class", "compliance_level",
		"new_status", "new_severity", "new_priority_class"}); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, w, nil
}

// Render prints the report for a person.
func Render(r *Report) string {
	var b strings.Builder
	mode := "DRY RUN (nothing changed)"
	if r.Apply {
		mode = "APPLIED, run " + r.RunID
	}
	fmt.Fprintf(&b, "compliance-checks: %s, %d tenant(s)\n", mode, len(r.Tenants))
	for _, t := range r.Tenants {
		fmt.Fprintf(&b, "\ntenant %s\n  open compliance findings %d (closed, untouched %d)\n", t.TenantID, t.Open, t.Closed)
		fmt.Fprintf(&b, "  by result %s\n", kv(t.ByResult))
		fmt.Fprintf(&b, "  control states to record %d (findings without a control %d)\n", t.Controls, t.NoControl)
		fmt.Fprintf(&b, "  re-classified %d: severity %s -> %s; moves %s; class moves %s; level set %d; kept severity override %d, class override %d\n",
			t.Reclassified, kv(t.SeverityBefore), kv(t.SeverityAfter), kv(t.SeverityMoves), kv(t.ClassMoves), t.LevelSet, t.KeptOverride, t.KeptClassOverride)
		fmt.Fprintf(&b, "  to close (no failure) %s\n", kv(t.ToClose))
		if r.Apply {
			fmt.Fprintf(&b, "  applied: states %d, findings changed %d, closed %d\n", t.StatesRecorded, t.Applied, t.ClosedApplied)
		}
		for _, bm := range t.Benchmarks {
			fmt.Fprintf(&b, "    benchmark %s: findings %d on %d assets, %s\n", bm.Key, bm.Findings, bm.Assets, kv(bm.ByResult))
		}
	}
	return b.String()
}

func kv(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", orNone(k), m[k]))
	}
	return strings.Join(parts, " ")
}

func databaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		return ""
	}
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(get("DB_USER", "openctem"), os.Getenv("DB_PASSWORD")),
		Host:     host + ":" + get("DB_PORT", "5432"),
		Path:     "/" + get("DB_NAME", "openctem"),
		RawQuery: "sslmode=" + url.QueryEscape(get("DB_SSLMODE", "disable")),
	}
	return u.String()
}

// readOnlyURL makes every transaction of the connection read-only: the
// server refuses any write, so a dry run cannot change anything.
func readOnlyURL(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		q.Set("default_transaction_read_only", "on")
		u.RawQuery = q.Encode()
		return u.String()
	}
	return dsn + " default_transaction_read_only=on"
}

func fail(code int, msg string) {
	fmt.Fprintln(os.Stderr, "compliance-checks: "+msg)
	os.Exit(code)
}
