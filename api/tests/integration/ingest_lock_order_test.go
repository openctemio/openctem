package integration

// Every batched write of findings rows takes its row locks in one global
// order, fingerprint in byte order (internal/infra/postgres/finding_lock_order.go).
// A writer that locked in another order (id, report order, a map's order)
// deadlocked against the upsert of new findings, which can only lock by
// fingerprint: Postgres aborted one of them (40P01), and a best-effort
// writer dropped its rows with a warning.
//
// This test runs the ingest writers next to each other and next to the
// finding-priority stamp and a person's bulk status move, all on the same
// findings, and counts the deadlocks the database detected. It runs in a
// private database so no other package's deadlock is counted.

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// lockedBuffer is an io.Writer the logger of concurrent uploads can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestIngest_ConcurrentFindingWritersTakeNoDeadlock(t *testing.T) {
	sqldb := testdb.PrivateDatabase(t, "ingestlocks", filepath.Join("..", "..", "migrations"))
	ctx := context.Background()
	var dbName string
	if err := sqldb.QueryRowContext(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	sqldb.SetMaxOpenConns(40)

	tid, sensorID := shared.NewID(), shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		tid.String(), "locks-"+tid.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, type,
		reported_tools, reported_tool_names, reported_at)
		VALUES ($1, $2, 'locks-sensor', $3, 'rda_test', 'active', 'worker', '[{"name":"semgrep","installed":true}]'::jsonb, $4, NOW())`,
		sensorID.String(), tid.String(), "h-"+sensorID.String(), pq.Array([]string{"semgrep"})); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}

	warnings := &lockedBuffer{}
	db := &postgres.DB{DB: sqldb}
	findingRepo := postgres.NewFindingRepository(db)
	scoring := postgres.NewScoringRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), findingRepo,
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.New(logger.Config{Level: "warn", Format: "text", Output: warnings}))
	repoName := "github.com/acme/locks-" + tid.String()[:8]

	report := func(n int, order []int) *ctis.Report {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(),
				Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + repoName}},
			Assets: []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: repoName}}}
		if order == nil {
			order = make([]int, n)
			for i := range order {
				order[i] = i
			}
		}
		for _, k := range order {
			rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability,
				Title: fmt.Sprintf("Injection sink %d", k), Severity: ctis.SeverityHigh, RuleID: fmt.Sprintf("rule.%d", k%9),
				AssetRef: "repo", Location: &ctis.FindingLocation{Path: fmt.Sprintf("src/f%d.go", k), StartLine: 10 + k%40,
					Snippet: fmt.Sprintf("query(%d)", k)}})
		}
		return rep
	}
	upload := func(rep *ctis.Report) error {
		agt := &sensor.Sensor{ID: sensorID, TenantID: &tid, Name: "ci-run", Status: sensor.SensorStatusActive}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{
			Route: "ci", RequireAssetForFindings: true, NoCatalogWrites: true, DeferSensorStats: true}})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			return fmt.Errorf("%s", strings.Join(out.Errors, "; "))
		}
		return nil
	}
	findingIDs := func() []shared.ID {
		rows, err := sqldb.QueryContext(ctx, `SELECT id FROM findings WHERE tenant_id = $1`, tid.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []shared.ID
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			id, _ := shared.IDFromString(s)
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return ids
	}

	const existing, added, uploads = 150, 60, 10
	if err := upload(report(existing, nil)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	ids := findingIDs()

	// Each round: uploads that re-report the existing findings and add the
	// same new ones, each in its own order, next to the priority stamp and a
	// person moving every finding to confirmed, each in its own id order.
	var (
		mu     sync.Mutex
		errs   []string
		rounds = 6
	)
	fail := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, fmt.Sprintf(format, a...))
	}
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < uploads; i++ {
			order := rand.New(rand.NewSource(int64(round*100 + i))).Perm(existing + added)
			rep := report(existing+added, order)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := upload(rep); err != nil {
					fail("upload: %.300v", err)
				}
			}()
		}
		for i := 0; i < 3; i++ {
			shuffled := append([]shared.ID(nil), ids...)
			rand.New(rand.NewSource(int64(round*10+i))).Shuffle(len(shuffled), func(a, b int) {
				shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
			})
			version := int64(1000 + round*10 + i)
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if err := scoring.StampVersion(ctx, tid, shuffled, version); err != nil {
					fail("stamp priority version: %v", err)
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				if _, err := findingRepo.MoveStatusBatch(ctx, tid, shuffled, nil, vulnerability.FindingStatusConfirmed,
					"", nil, vulnerability.Closure{}); err != nil {
					fail("move status: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}

	var rowsN, sum int
	if err := sqldb.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(occurrence_count), 0) FROM findings WHERE tenant_id = $1`,
		tid.String()).Scan(&rowsN, &sum); err != nil {
		t.Fatal(err)
	}
	if want := existing*(1+rounds*uploads) + added*rounds*uploads; rowsN != existing+added || sum != want {
		t.Errorf("rows=%d sum(occurrence_count)=%d, want %d, %d (a sighting was lost)", rowsN, sum, existing+added, want)
	}
	for _, e := range errs {
		t.Error(e)
	}
	for _, line := range strings.Split(warnings.String(), "\n") {
		if strings.Contains(line, "deadlock") || strings.Contains(line, "40P01") {
			t.Errorf("a write was dropped on a deadlock: %.400s", line)
		}
	}
	if n := deadlocksDetected(t, sqldb, dbName); n != 0 {
		t.Errorf("the database detected %d deadlocks between finding writers, want 0 (a writer locks findings rows out of the global order)", n)
	}
}

// deadlocksDetected closes db, waits until its server backends have exited
// (a backend flushes its statistics on exit) and returns the deadlocks the
// database counted.
func deadlocksDetected(t *testing.T, db *sql.DB, dbName string) int64 {
	t.Helper()
	_ = db.Close()
	admin, err := sql.Open("postgres", testdb.AdminURL())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	ctx := context.Background()
	for deadline := time.Now().Add(15 * time.Second); ; {
		var backends int
		if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = $1`, dbName).Scan(&backends); err != nil {
			t.Fatal(err)
		}
		if backends == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backends of %s still open", backends, dbName)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := admin.ExecContext(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := admin.QueryRowContext(ctx, `SELECT COALESCE(deadlocks, 0) FROM pg_stat_database WHERE datname = $1`, dbName).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// failingOccurrences is the finding repository with a branch occurrence
// write that fails, as a conflict that outlived its retries would.
type failingOccurrences struct {
	*postgres.FindingRepository
	fail bool
}

func (f *failingOccurrences) UpsertBranchOccurrences(ctx context.Context, tenantID shared.ID, items []vulnerability.BranchOccurrenceUpsert) error {
	if f.fail {
		return fmt.Errorf("pq: deadlock detected")
	}
	return f.FindingRepository.UpsertBranchOccurrences(ctx, tenantID, items)
}

// A scan whose branch occurrences could not be written says so in its
// result and does not sweep the branch: the sweep would mark the findings it
// saw as gone from the branch (auto_fixed), because their occurrences still
// carry the previous scan.
func TestIngest_FailedBranchOccurrenceWriteSkipsTheSweep(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("semgrep")
	db := &postgres.DB{DB: r.db}
	repo := &failingOccurrences{FindingRepository: postgres.NewFindingRepository(db)}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), repo,
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	ctx := context.Background()
	scan := func(id string) (*ingest.Output, error) {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{ID: id, Timestamp: time.Now().UTC(), CoverageType: "full",
				Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + tn.repo}},
			Assets: []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: tn.repo}},
			Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "Injection sink", Severity: ctis.SeverityHigh,
				RuleID: "rule.1", AssetRef: "repo", Location: &ctis.FindingLocation{Path: "src/a.go", StartLine: 10}}}}
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Name: "ci-run", Status: sensor.SensorStatusActive}
		return svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{
			Route: "ci", RequireAssetForFindings: true, NoCatalogWrites: true, DeferSensorStats: true}})
	}
	occurrence := func() (status, lastScan string) {
		t.Helper()
		if err := r.db.QueryRow(`SELECT o.status, COALESCE(o.last_seen_scan_id, '') FROM finding_branch_occurrences o
			JOIN findings f ON f.id = o.finding_id WHERE f.tenant_id = $1`, tid.String()).Scan(&status, &lastScan); err != nil {
			t.Fatal(err)
		}
		return status, lastScan
	}

	if out, err := scan("scan-1"); err != nil || len(out.Errors) > 0 {
		t.Fatalf("first scan: %v %v", err, out)
	}
	if status, last := occurrence(); status != "open" || last != "scan-1" {
		t.Fatalf("after the first scan: occurrence %s, last seen in %q", status, last)
	}

	repo.fail = true
	out, err := scan("scan-2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(out.Errors, "; "), "record branch occurrences") {
		t.Errorf("the failed occurrence write is not in the result: %v", out.Errors)
	}
	if status, _ := occurrence(); status != "open" {
		t.Errorf("the scan that saw the finding marked its occurrence %s, want open", status)
	}
}
