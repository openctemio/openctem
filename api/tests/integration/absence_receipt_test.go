package integration

// Absence is decided from the run's receipt, not from findings.scan_id. A
// finding the run reported has an action row on the run's receipt; scan_id
// only says which report wrote it last. A concurrent run of the same tool and
// profile overwrites scan_id with its own report id, and a sighting write
// that lost a deadlock leaves the previous one: both made a finding the run
// did report look unreported, and the coverage evaluation closed it.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newAbsenceRun(t *testing.T) *repoRun {
	t.Helper()
	var results *postgres.SensorResultRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		results = postgres.NewSensorResultRepository(db)
		svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
		svc.SetCommandReader(postgres.NewCommandRepository(db))
		svc.SetCoverageAutoResolve(ingest.CoverageAutoResolveDryRun, ingest.DefaultBlindingGuard())
		svc.SetReceiptRecorder(postgres.NewIngestReceiptRepository(db))
	})
	return &repoRun{r: r, tn: r.newTenant("semgrep"), results: results}
}

// segmentOf opens a report of cmd and processes its one segment (the
// findings are written), without committing it.
func (rr *repoRun) segmentOf(cmd shared.ID, rules ...string) *ingestreport.Report {
	fs := make([]v2Finding, 0, len(rules))
	for _, rule := range rules {
		fs = append(fs, v2Finding{rule: rule, assetRef: "repo"})
	}
	seg := rr.tn.segment("semgrep", true, fs...)
	rep := rr.r.openAs(rr.tn, shared.NewID().String(), "worker", &cmd, seg)
	rr.r.put(rr.tn, rep, 0, seg)
	rr.r.process(rep, 0)
	return rep
}

func (rr *repoRun) statusOf(rule string) string {
	rr.r.t.Helper()
	var st string
	if err := rr.r.db.QueryRow(`SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = $2`,
		rr.tn.tenant.String(), rule).Scan(&st); err != nil {
		rr.r.t.Fatal(err)
	}
	return st
}

// Two runs of the same profile report "kept"; run B writes its sighting
// after run A's. A's evaluation must not close "kept" (B's report id is now
// its scan_id) and must still close what neither reported.
func TestAbsence_ConcurrentRunOverwritingScanIDDoesNotClose(t *testing.T) {
	rr := newAbsenceRun(t)
	p := rr.r.scanProfile(rr.tn, "p-default")
	baseline := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	if st := rr.send(baseline, "kept", "gone"); st.Accepted.Findings != 2 {
		t.Fatalf("baseline: %+v", st)
	}

	cmdA := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	cmdB := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	repA := rr.segmentOf(cmdA, "kept")
	repB := rr.segmentOf(cmdB, "kept")
	if !rr.r.commit(rr.tn, repA, 1) {
		t.Fatal("commit A refused")
	}
	if got := rr.statusOf("kept"); got == "resolved" {
		t.Fatal("run A closed a finding it reported, because run B's sighting overwrote its scan_id")
	}
	if got := rr.statusOf("gone"); got != "resolved" {
		t.Fatalf("gone: status %q, want resolved (neither run reported it)", got)
	}
	if !rr.r.commit(rr.tn, repB, 1) {
		t.Fatal("commit B refused")
	}
	if got := rr.statusOf("kept"); got == "resolved" {
		t.Fatal("run B closed a finding it reported")
	}
}

// A run whose sighting write was lost (the finding keeps an earlier run's
// scan_id) still reported the finding: its receipt says so.
func TestAbsence_LostSightingDoesNotClose(t *testing.T) {
	rr := newAbsenceRun(t)
	p := rr.r.scanProfile(rr.tn, "p-default")
	baseline := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	if st := rr.send(baseline, "kept", "gone"); st.Accepted.Findings != 2 {
		t.Fatalf("baseline: %+v", st)
	}
	var baselineScan string
	if err := rr.r.db.QueryRow(`SELECT scan_id FROM findings WHERE tenant_id = $1 AND rule_id = 'kept'`,
		rr.tn.tenant.String()).Scan(&baselineScan); err != nil {
		t.Fatal(err)
	}

	cmd := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	rep := rr.segmentOf(cmd, "kept")
	// The sighting write of "kept" lost a deadlock: scan_id is still the
	// baseline run's.
	if _, err := rr.r.db.Exec(`UPDATE findings SET scan_id = $3 WHERE tenant_id = $1 AND rule_id = $2`,
		rr.tn.tenant.String(), "kept", baselineScan); err != nil {
		t.Fatal(err)
	}
	if !rr.r.commit(rr.tn, rep, 1) {
		t.Fatal("commit refused")
	}
	if got := rr.statusOf("kept"); got == "resolved" {
		t.Fatal("a reported finding whose sighting write was lost was closed")
	}
	if got := rr.statusOf("gone"); got != "resolved" {
		t.Fatalf("gone: status %q, want resolved", got)
	}
}

// Many runs of the same profile, all reporting the same findings, process
// and commit at the same time: none of those findings is closed.
func TestAbsence_ConcurrentRunsNeverCloseWhatTheyReported(t *testing.T) {
	rr := newAbsenceRun(t)
	p := rr.r.scanProfile(rr.tn, "p-default")
	rules := []string{"r1", "r2", "r3", "r4", "r5", "r6"}
	baseline := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	if st := rr.send(baseline, append([]string{"gone"}, rules...)...); st.Accepted.Findings != len(rules)+1 {
		t.Fatalf("baseline: %+v", st)
	}

	const runs = 8
	cmds := make([]shared.ID, runs)
	for i := range cmds {
		cmds[i] = rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	}
	reps := make([]*ingestreport.Report, runs)
	var wg sync.WaitGroup
	for i := range cmds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reps[i] = rr.segmentOf(cmds[i], rules...)
		}(i)
	}
	wg.Wait()
	for i := range reps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			if ok, err := rr.r.reports.Commit(ctx, reps[i].ID, ingestreport.CommitFacts{SegmentCount: 1, Integrity: "single"}, reps[i].ReceivedAt); err != nil || !ok {
				t.Errorf("commit %d: %v %v", i, ok, err)
			}
		}(i)
	}
	wg.Wait()
	// Commit jobs: the coverage evaluation of every run.
	for i := range reps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr.processCommit(reps[i])
		}(i)
	}
	wg.Wait()

	for _, rule := range rules {
		if got := rr.statusOf(rule); got == "resolved" {
			t.Errorf("%s: closed by a concurrent run although every run reported it", rule)
		}
	}
	if got := rr.statusOf("gone"); got != "resolved" {
		t.Errorf("gone: status %q, want resolved", got)
	}
}

// processCommit runs the commit job of a committed report (finalize and the
// coverage evaluation of its command).
func (rr *repoRun) processCommit(rep *ingestreport.Report) {
	ctx := context.Background()
	job := ingestjob.NewV2Job(rr.tn.tenant, &rr.tn.sensor, rep.ReportID, ingestjob.V2Segment{ReportRef: rep.ID}, nil)
	job.DelayUntil(time.Now().Add(24 * time.Hour))
	queued, _, err := rr.r.jobs.EnqueueV2(ctx, job)
	if err != nil {
		rr.r.t.Errorf("enqueue commit: %v", err)
		return
	}
	if _, err := rr.r.proc.Process(ctx, queued); err != nil {
		rr.r.t.Errorf("process commit: %v", err)
	}
}

// failingReceipts stands in for a receipt store that cannot be written.
type failingReceipts struct{}

func (failingReceipts) Record(context.Context, *ingestreceipt.Delta) (shared.ID, error) {
	return shared.ID{}, errors.New("receipt store unavailable")
}

// A segment of a command's run whose receipt cannot be written fails (the
// queue retries it) instead of applying without its action rows, which would
// let the run's coverage evaluation see its findings as unreported.
func TestAbsence_SegmentWithoutReceiptIsRetried(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetCommandReader(postgres.NewCommandRepository(db))
		svc.SetReceiptRecorder(failingReceipts{})
	})
	tn := r.newTenant("semgrep")
	cmd := r.runCommand(tn, "semgrep", r.scanProfile(tn, "p"), "completed", 0)
	seg := tn.segment("semgrep", true, v2Finding{rule: "kept", assetRef: "repo"})
	rep := r.openAs(tn, shared.NewID().String(), "worker", &cmd, seg)
	r.put(tn, rep, 0, seg)
	job, err := r.jobs.GetV2Segment(context.Background(), rep.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.proc.Process(context.Background(), job); err == nil {
		t.Fatal("a command-bound segment whose receipt was not written was accepted")
	}
}
