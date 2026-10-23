package integration

// Ingest query budget: one import of a checked-in CTIS report and three
// re-imports (unchanged, one finding gone, one finding new) run through the
// real ingest service on a migrated database, with the SQL statements of each
// phase counted. A phase that sends more statements than its entry in
// testdata/ingest_budget.json fails the test, so a change that turns a
// per-report cost into a per-finding cost (an N+1) is caught before it ships.
//
// A change that legitimately needs more statements, or saves some, rewrites
// the budget with `make budgets-update` (from api/, or the repository root);
// the diff of the budget file is then part of the review.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/internal/testdb/sqlcount"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var updateBudgets = flag.Bool("update-budgets", false, "rewrite testdata/ingest_budget.json with the measured counts")

const (
	ingestBudgetFile   = "testdata/ingest_budget.json"
	ingestBudgetReport = "testdata/ingest_budget/report.json"
)

// phaseBudget is the most one phase may send.
type phaseBudget struct {
	Statements   int `json:"statements"`
	Transactions int `json:"transactions"`
}

type ingestBudget struct {
	Comment string                 `json:"_comment"`
	Phases  map[string]phaseBudget `json:"phases"`
}

// budgetPhases is the order of the phases, which is also the order they run.
var budgetPhases = []string{"import", "reimport_unchanged", "reimport_finding_gone", "reimport_finding_new"}

func loadIngestReport(t *testing.T) *ctis.Report {
	t.Helper()
	raw, err := os.ReadFile(ingestBudgetReport)
	if err != nil {
		t.Fatal(err)
	}
	// The vulnerability catalog is shared by every test of the database, and
	// whether a CVE is already in it changes the statement count. Each run
	// gets CVE ids of its own so the first import always meets an empty catalog.
	run := digits(shared.NewID().String())
	seen := map[string]string{}
	text := cveID.ReplaceAllStringFunc(string(raw), func(cve string) string {
		if _, ok := seen[cve]; !ok {
			seen[cve] = fmt.Sprintf("CVE-2099-%s%d", run, len(seen)+1)
		}
		return seen[cve]
	})
	var rep ctis.Report
	if err := json.Unmarshal([]byte(text), &rep); err != nil {
		t.Fatalf("%s: %v", ingestBudgetReport, err)
	}
	return &rep
}

var cveID = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

// digits keeps the first six decimal digits of s.
func digits(s string) string {
	out := make([]byte, 0, 6)
	for i := 0; i < len(s) && len(out) < 6; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	for len(out) < 6 {
		out = append(out, '0')
	}
	return string(out)
}

// cloneReport copies a report (the ingest service rewrites the report it is
// given) and gives it a fresh id, as a new scan would have.
func cloneReport(t *testing.T, rep *ctis.Report, mutate func(*ctis.Report)) *ctis.Report {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var out ctis.Report
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	out.Metadata.ID = shared.NewID().String()
	out.Metadata.Timestamp = time.Now().UTC()
	if mutate != nil {
		mutate(&out)
	}
	return &out
}

func TestIngestQueryBudget(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping the ingest query budget")
	}
	counter := &sqlcount.Counter{}
	sqldb, err := sqlcount.Open(dsn, counter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Fatalf("database not available: %v", err)
	}

	r := &v2Rig{t: t, db: sqldb}
	db := &postgres.DB{DB: sqldb}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("ingest-budget-server-secret-0123456789")))

	base := loadIngestReport(t)
	tn := r.newTenant(base.Tool.Name)
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	countFindings := func() int {
		var n int
		if err := sqldb.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND status <> 'duplicate'`,
			tn.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	total := len(base.Findings)
	phases := map[string]struct {
		mutate func(*ctis.Report)
		// findings is how many findings the tenant holds after the phase.
		findings int
	}{
		"import":             {nil, total},
		"reimport_unchanged": {nil, total},
		"reimport_finding_gone": {func(rep *ctis.Report) {
			rep.Findings = rep.Findings[:len(rep.Findings)-1]
		}, total},
		"reimport_finding_new": {func(rep *ctis.Report) {
			f := rep.Findings[0]
			loc := *f.Location // a copy: the first finding keeps its own location
			f.Location = &loc
			f.ID = "new-1"
			f.Title = "A finding that appeared in this scan"
			f.RuleID = "python.django.security.injection.sql-new"
			f.Location.Path = "app/new_module.py"
			rep.Findings = append(rep.Findings, f)
		}, total + 1},
	}

	measured := map[string]phaseBudget{}
	verbs := map[string]map[string]int{}
	for _, name := range budgetPhases {
		p := phases[name]
		rep := cloneReport(t, base, p.mutate)
		counter.Reset()
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
		// The audit entry and the sensor counters are written by goroutines the
		// call leaves behind: wait for them so they count in this phase.
		snap := counter.Settle(400*time.Millisecond, 15*time.Second)
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("%s: ingest: %v %v", name, err, out.Errors)
		}
		if got := countFindings(); got != p.findings {
			t.Fatalf("%s: the tenant holds %d findings, want %d (the phase did not do what its name says)", name, got, p.findings)
		}
		measured[name] = phaseBudget{Statements: snap.Statements, Transactions: snap.Transactions}
		verbs[name] = snap.Verbs
	}

	if *updateBudgets {
		writeIngestBudget(t, measured)
		return
	}

	raw, err := os.ReadFile(ingestBudgetFile)
	if err != nil {
		t.Fatalf("%v (run `make budgets-update` to create it)", err)
	}
	var budget ingestBudget
	if err := json.Unmarshal(raw, &budget); err != nil {
		t.Fatalf("%s: %v", ingestBudgetFile, err)
	}
	for _, name := range budgetPhases {
		want, ok := budget.Phases[name]
		if !ok {
			t.Errorf("%s: no budget for this phase in %s (run `make budgets-update`)", name, ingestBudgetFile)
			continue
		}
		got := measured[name]
		t.Logf("%s: %d statements (budget %d), %d transactions (budget %d), by kind %s",
			name, got.Statements, want.Statements, got.Transactions, want.Transactions, formatVerbs(verbs[name]))
		if got.Statements > want.Statements {
			t.Errorf("%s: %d SQL statements, budget %d. A report with %d findings should not cost more per finding than before. "+
				"If the extra statements are intended, run `make budgets-update` and explain them in the pull request. By kind: %s",
				name, got.Statements, want.Statements, total, formatVerbs(verbs[name]))
		}
		if got.Transactions > want.Transactions {
			t.Errorf("%s: %d transactions, budget %d (run `make budgets-update` if intended)", name, got.Transactions, want.Transactions)
		}
		if got.Statements < want.Statements || got.Transactions < want.Transactions {
			t.Logf("%s: under budget; `make budgets-update` locks the saving in", name)
		}
	}
	for name := range budget.Phases {
		if _, ok := measured[name]; !ok {
			t.Errorf("%s: the budget names a phase this test no longer runs", name)
		}
	}
}

func writeIngestBudget(t *testing.T, measured map[string]phaseBudget) {
	t.Helper()
	b := ingestBudget{
		Comment: "SQL statements per phase of TestIngestQueryBudget (tests/integration/ingest_budget_test.go). " +
			"Regenerate with `make budgets-update` and review the diff.",
		Phases: measured,
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ingestBudgetFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ingestBudgetFile, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", ingestBudgetFile)
}

func formatVerbs(v map[string]int) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s=%d", k, v[k])
	}
	return out
}

// The counter must see what the repositories send, or a budget of zero would
// pass for ever: this proves each kind of call is counted.
func TestSQLCounterSeesQueriesExecsAndTransactions(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping")
	}
	c := &sqlcount.Counter{}
	db, err := sqlcount.Open(dsn, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	c.Reset()
	var one int
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `SELECT 2`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := tx.PrepareContext(ctx, `SELECT $1::int`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for i := 0; i < 3; i++ {
		if err := st.QueryRowContext(ctx, i).Scan(&one); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s := c.Snapshot()
	if s.Statements != 5 || s.Transactions != 1 || s.Verbs["SELECT"] != 5 {
		t.Fatalf("counted %+v, want 5 statements (1 query, 1 exec, 3 prepared runs) in 1 transaction", s)
	}
}
