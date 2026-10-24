package integration

// Ingest load harness (docs/rfcs/RFC-122-ingest-receipts.md, "Load
// targets"). It drives the real CI upload path (HTTP accept, sealed storage,
// the ingest queue, workers, the ingest core) against a migrated Postgres and
// checks the acceptance targets. It runs only with INGEST_LOAD=1 (the
// nightly "Ingest load" workflow, on a fresh database); knobs:
//
//	LOAD_CONC=50 LOAD_FINDINGS=1000 LOAD_TENANTS=10   concurrent uploads (T1)
//	LOAD_BULK=500                                     bulk jobs queued ahead of a KEV/critical report (T4)
//	LOAD_SAME=20 LOAD_SAME_FINDINGS=500               uploads of the same findings to one repository (T3)
//	LOAD_WORKERS=4                                    ingest workers
//	LOAD_SUMMARY=<file>                               a markdown table of the results is appended here
//
// Targets: T1 0 failed uploads and every finding stored; T4 the urgent
// report applied within 15 s while the bulk jobs wait; T3 0 failed uploads
// and no lost sighting (every run records every finding it reported, one
// finding per fingerprint); no deadlock surfaces as a failed job.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func loadEnv(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return d
}

type loadResult struct {
	name, target, measured string
	ok                     bool
}

type loadHarness struct {
	t       *testing.T
	r       *ciRig
	workers int
	results []loadResult
	nextSHA int
	trusts  map[shared.ID]*cirun.TrustConfig
	host    string
}

func (h *loadHarness) record(name, target, measured string, ok bool) {
	h.results = append(h.results, loadResult{name, target, measured, ok})
	if !ok {
		h.t.Errorf("%s: %s (target %s)", name, measured, target)
	}
}

// openRun opens a CI run of the tenant on project (owner/name) and returns
// its token, id and repository name.
func (h *loadHarness) openRun(tenant shared.ID, project string) (string, string, string) {
	h.t.Helper()
	cfg := h.trusts[tenant]
	if cfg == nil {
		cfg = h.r.trust(tenant, cirun.Rules{Owners: []string{"acme"}})
		h.trusts[tenant] = cfg
	}
	h.nextSHA++
	sha := fmt.Sprintf("%040x", h.nextSHA)
	code, ex := h.r.exchange(tenant, h.r.idp.token(h.t, cfg.Audience, project, "main", sha,
		map[string]any{"job_id": strconv.Itoa(h.nextSHA)}))
	if code != http.StatusCreated {
		h.t.Fatalf("exchange %s: %d %v", project, code, ex)
	}
	return ex["token"].(string), ex["run_id"].(string), h.host + "/" + project
}

func loadFindings(prefix string, from, n int, sev string) []ctis.Finding {
	fs := make([]ctis.Finding, 0, n)
	for i := from; i < from+n; i++ {
		fs = append(fs, ciFinding(fmt.Sprintf("%s-%d", prefix, i), fmt.Sprintf("load.rule.%d", i), sev,
			ctis.FindingTypeVulnerability, fmt.Sprintf("src/f%d.go", i), i+1))
	}
	return fs
}

type upload struct{ token, run, repo string }

// acceptAll posts every report concurrently (at most LOAD_ACCEPT_PARALLEL
// requests in flight, default 50: the API's own connection pool is the
// production bound) and returns the accept latencies and the failures
// (anything but 202).
func (h *loadHarness) acceptAll(ups []upload, bodies []map[string]any) ([]time.Duration, int) {
	lat := make([]time.Duration, len(ups))
	codes := make([]int, len(ups))
	slots := make(chan struct{}, loadEnv("LOAD_ACCEPT_PARALLEL", 50))
	var wg sync.WaitGroup
	for i := range ups {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			t0 := time.Now()
			resp, _ := h.r.post("/api/v1/ci/runs/"+ups[i].run+"/results", ups[i].token, bodies[i])
			lat[i], codes[i] = time.Since(t0), resp.StatusCode
		}(i)
	}
	wg.Wait()
	failed := 0
	for _, c := range codes {
		if c != http.StatusAccepted {
			failed++
		}
	}
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	return lat, failed
}

// drain runs the workers until the queue is empty.
func (h *loadHarness) drain(ctx context.Context) time.Duration {
	t0 := time.Now()
	w := controller.NewIngestWorkerController(h.r.jobs, h.r.jp, &controller.IngestWorkerControllerConfig{
		Workers: h.workers, MaxPerTick: 100000, LeaseTimeout: 30 * time.Minute})
	for {
		n, err := w.Reconcile(ctx)
		if ctx.Err() != nil {
			return time.Since(t0) // stopped by the caller
		}
		if err != nil {
			h.t.Errorf("drain: %v", err)
			return time.Since(t0)
		}
		if n == 0 {
			return time.Since(t0)
		}
	}
}

func (h *loadHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *loadHarness) deadlocks() int {
	return h.count(`SELECT deadlocks::int FROM pg_stat_database WHERE datname = current_database()`)
}

func pct(lat []time.Duration, p int) time.Duration {
	if len(lat) == 0 {
		return 0
	}
	return lat[min(len(lat)-1, len(lat)*p/100)]
}

func TestIngestLoad(t *testing.T) {
	if os.Getenv("INGEST_LOAD") != "1" {
		t.Skip("ingest load harness: set INGEST_LOAD=1 (nightly)")
	}
	r := newCIRig(t)
	// The API's pool plus the ingest pool in production (25 + 8), with
	// headroom for the harness's own reads.
	r.db.SetMaxOpenConns(loadEnv("LOAD_DB_CONNS", 60))
	h := &loadHarness{t: t, r: r, workers: loadEnv("LOAD_WORKERS", 4), trusts: map[shared.ID]*cirun.TrustConfig{},
		host: strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://"))}
	ctx := context.Background()
	tenants := []shared.ID{r.tenant, r.other}
	for len(tenants) < loadEnv("LOAD_TENANTS", 10) {
		tenants = append(tenants, r.newTenant())
	}
	deadlocksBefore := h.deadlocks()

	// --- T1: concurrent uploads, half of the findings already known ---
	conc, nf := loadEnv("LOAD_CONC", 50), loadEnv("LOAD_FINDINGS", 1000)
	type repoRef struct {
		tenant  shared.ID
		project string
	}
	repos := make([]repoRef, conc)
	for i := range repos {
		repos[i] = repoRef{tenants[i%len(tenants)], fmt.Sprintf("acme/load-%d", i)}
	}
	seed := make([]upload, conc)
	seedBodies := make([]map[string]any, conc)
	for i, rr := range repos {
		tok, run, repo := h.openRun(rr.tenant, rr.project)
		seed[i] = upload{tok, run, repo}
		seedBodies[i] = ciReport(repo, loadFindings("L", 0, nf/2, "medium")...)
	}
	if _, failed := h.acceptAll(seed, seedBodies); failed > 0 {
		t.Fatalf("seed round: %d uploads refused", failed)
	}
	h.drain(ctx)
	ups := make([]upload, conc)
	bodies := make([]map[string]any, conc)
	for i, rr := range repos {
		tok, run, repo := h.openRun(rr.tenant, rr.project)
		ups[i] = upload{tok, run, repo}
		bodies[i] = ciReport(repo, loadFindings("L", 0, nf, "medium")...)
	}
	start := time.Now()
	lat, refused := h.acceptAll(ups, bodies)
	drained := h.drain(ctx)
	wall := time.Since(start)
	dead := h.count(`SELECT count(*) FROM ingest_jobs WHERE kind = 'ci_results' AND status = 'dead'`)
	stored := h.count(`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE a.name LIKE $1`, h.host+"/acme/load-%")
	jobP95 := time.Duration(h.count(`SELECT COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM updated_at - created_at) * 1000), 0)::int
		FROM ingest_jobs WHERE kind = 'ci_results' AND status = 'completed' AND created_at >= $1`, start)) * time.Millisecond
	h.record("T1 uploads refused or failed", "0", fmt.Sprintf("%d refused, %d failed of %d", refused, dead, conc), refused == 0 && dead == 0)
	h.record("T1 findings stored", strconv.Itoa(conc*nf), strconv.Itoa(stored), stored == conc*nf)
	h.record("T1 accept p50 / p95", "reported", fmt.Sprintf("%s / %s", pct(lat, 50).Round(time.Millisecond), pct(lat, 95).Round(time.Millisecond)), true)
	h.record("T1 job p95 (accept to applied)", "reported", jobP95.Round(time.Millisecond).String(), true)
	h.record("T1 queue drained", "reported", fmt.Sprintf("%s (wall %s, %d workers)", drained.Round(time.Millisecond), wall.Round(time.Millisecond), h.workers), true)

	// --- T4: an urgent report while bulk jobs wait ---
	bulk := loadEnv("LOAD_BULK", 500)
	bulkUps := make([]upload, bulk)
	bulkBodies := make([]map[string]any, bulk)
	for i := range bulkUps {
		tok, run, repo := h.openRun(tenants[i%len(tenants)], fmt.Sprintf("acme/bulk-%d", i))
		bulkUps[i] = upload{tok, run, repo}
		bulkBodies[i] = ciReport(repo, loadFindings("B", 0, 50, "low")...)
	}
	if _, failed := h.acceptAll(bulkUps, bulkBodies); failed > 0 {
		t.Fatalf("bulk round: %d uploads refused", failed)
	}
	// They stand for scheduled sensor runs: the bulk lane.
	if _, err := r.db.ExecContext(ctx, `UPDATE ingest_jobs SET lane = 2 WHERE status = 'pending' AND kind = 'ci_results'`); err != nil {
		t.Fatal(err)
	}
	drainCtx, stop := context.WithCancel(ctx)
	drainDone := make(chan time.Duration, 1)
	go func() { drainDone <- h.drain(drainCtx) }()
	time.Sleep(500 * time.Millisecond) // the workers are busy with bulk work
	urgentTenant := r.newTenant()
	tok, run, repo := h.openRun(urgentTenant, "acme/urgent")
	t0 := time.Now()
	resp, out := r.post("/api/v1/ci/runs/"+run+"/results", tok, ciReport(repo, loadFindings("U", 0, 20, "critical")...))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("urgent upload: %d %v", resp.StatusCode, out)
	}
	uid := out["upload_id"].(string)
	var urgentLatency time.Duration
	for {
		_, st := r.get("/api/v1/ci/runs/"+run+"/results/"+uid+"?wait=1", tok)
		if st["status"] == "applied" || st["status"] == "failed" || time.Since(t0) > 2*time.Minute {
			urgentLatency = time.Since(t0)
			if st["status"] != "applied" {
				t.Errorf("urgent report: %v", st)
			}
			break
		}
	}
	waiting := h.count(`SELECT count(*) FROM ingest_jobs WHERE status = 'pending' AND lane = 2`)
	stop()
	<-drainDone
	h.drain(ctx)
	h.record("T4 urgent report applied while bulk waits", "< 15s", fmt.Sprintf("%s (%d bulk jobs still waiting)", urgentLatency.Round(time.Millisecond), waiting),
		urgentLatency < 15*time.Second)

	// --- T3: the same findings to one repository from many runs at once ---
	same, sameN := loadEnv("LOAD_SAME", 20), loadEnv("LOAD_SAME_FINDINGS", 500)
	sameUps := make([]upload, same)
	sameBodies := make([]map[string]any, same)
	for i := range sameUps {
		tok, run, repo := h.openRun(tenants[0], "acme/matrix")
		sameUps[i] = upload{tok, run, repo}
		sameBodies[i] = ciReport(repo, loadFindings("M", 0, sameN, "medium")...)
	}
	_, refused = h.acceptAll(sameUps, sameBodies)
	h.drain(ctx)
	matrixFindings := h.count(`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id WHERE a.name = $1`, h.host+"/acme/matrix")
	short := 0
	for _, u := range sameUps {
		if n := h.count(`SELECT count(*) FROM ci_run_findings WHERE run_id = $1`, u.run); n != sameN {
			short++
		}
	}
	deadSame := h.count(`SELECT count(*) FROM ingest_jobs WHERE kind = 'ci_results' AND status = 'dead'`) - dead
	h.record("T3 uploads refused or failed", "0", fmt.Sprintf("%d refused, %d failed of %d", refused, deadSame, same), refused == 0 && deadSame == 0)
	h.record("T3 one finding per fingerprint", strconv.Itoa(sameN), strconv.Itoa(matrixFindings), matrixFindings == sameN)
	h.record("T3 runs with a lost sighting", "0", fmt.Sprintf("%d of %d", short, same), short == 0)

	deadlocks := h.deadlocks() - deadlocksBefore
	h.record("Deadlocks (retried, never surfaced)", "reported; 0 failed jobs", strconv.Itoa(deadlocks), true)

	var b strings.Builder
	b.WriteString("| Scenario | Target | Measured | |\n|---|---|---|---|\n")
	for _, res := range h.results {
		mark := "pass"
		if !res.ok {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", res.name, res.target, res.measured, mark)
	}
	t.Log("\n" + b.String())
	if path := os.Getenv("LOAD_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- the CI job's own summary file
		if err == nil {
			_, _ = f.WriteString("### Ingest load\n\n" + b.String() + "\n")
			_ = f.Close()
		}
	}
}
