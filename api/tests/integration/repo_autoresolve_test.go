package integration

// Research 18 F3: a scan closes default-branch (repository) findings only
// through the per-command evaluation of a protocol v2 run that proves it ran
// the same check cleanly. Each test first establishes a baseline (rules a and
// gone, seen by a clean bound run) and then sends a run that no longer
// reports "gone": only the last test's run may close it.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

type repoRun struct {
	r       *v2Rig
	tn      v2Tenant
	results *postgres.SensorResultRepository
}

func newRepoRun(t *testing.T) *repoRun {
	t.Helper()
	r, results := newBindingV2Rig(t)
	return &repoRun{r: r, tn: r.newTenant("semgrep"), results: results}
}

// send sends one whole report of a run bound to cmd.
func (rr *repoRun) send(cmd shared.ID, rules ...string) protov2.Status {
	fs := make([]v2Finding, 0, len(rules))
	for _, rule := range rules {
		fs = append(fs, v2Finding{rule: rule, assetRef: "repo"})
	}
	seg := rr.tn.segment("semgrep", true, fs...)
	return rr.r.sendWhole(rr.tn, rr.r.openAs(rr.tn, shared.NewID().String(), "worker", &cmd, seg), seg)
}

func (rr *repoRun) baseline(profileID string) {
	rr.r.t.Helper()
	cmd := rr.r.runCommand(rr.tn, "semgrep", profileID, "completed", 0)
	if st := rr.send(cmd, "a", "gone"); st.Accepted.Findings != 2 {
		rr.r.t.Fatalf("baseline: %+v", st)
	}
}

func (rr *repoRun) goneStatus() string {
	rr.r.t.Helper()
	var st string
	if err := rr.r.db.QueryRow(`SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = 'gone'`,
		rr.tn.tenant.String()).Scan(&st); err != nil {
		rr.r.t.Fatal(err)
	}
	return st
}

// A run whose scanner exited non-zero (semgrep with errors, a crash) proves
// nothing about what it did not report.
func TestRepoAutoResolve_NonZeroExitNeverCloses(t *testing.T) {
	rr := newRepoRun(t)
	rr.baseline("")
	cmd := rr.r.runCommand(rr.tn, "semgrep", "", "completed", 2)
	if st := rr.send(cmd, "a"); st.AutoResolve != protov2.AutoResolveSkipped || st.AutoResolved != 0 {
		t.Fatalf("non-zero exit: %+v", st)
	}
	if got := rr.goneStatus(); got == "resolved" {
		t.Fatal("a run that exited 2 closed a finding")
	}
}

// A run whose command has not finished cannot close at commit time; once the
// command completes cleanly, the completion evaluates it and closes.
func TestRepoAutoResolve_WaitsForTheCommandToComplete(t *testing.T) {
	rr := newRepoRun(t)
	rr.baseline("")
	cmd := rr.r.runCommand(rr.tn, "semgrep", "", "running", 0)
	if st := rr.send(cmd, "a"); st.AutoResolve != protov2.AutoResolveSkipped {
		t.Fatalf("commit before completion: %+v", st)
	}
	if got := rr.goneStatus(); got == "resolved" {
		t.Fatal("closed before the command completed")
	}
	// The command fails: still nothing.
	if _, err := rr.r.db.Exec(`UPDATE commands SET status = 'failed' WHERE id = $1`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	rr.r.svc.EvaluateCommandCoverage(context.Background(), rr.tn.tenant, cmd)
	if got := rr.goneStatus(); got == "resolved" {
		t.Fatal("a failed command closed a finding")
	}
	// Completed with exit 0: the completion hook closes it.
	if _, err := rr.r.db.Exec(`UPDATE commands SET status = 'completed' WHERE id = $1`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	out := rr.r.svc.EvaluateCommandCoverage(context.Background(), rr.tn.tenant, cmd)
	if len(out.Resolved) != 1 {
		t.Fatalf("completion evaluation: %+v", out)
	}
	if got := rr.goneStatus(); got != "resolved" {
		t.Fatalf("status %q, want resolved", got)
	}
	var method string
	_ = rr.r.db.QueryRow(`SELECT resolution_method FROM findings WHERE tenant_id = $1 AND rule_id = 'gone'`, rr.tn.tenant.String()).Scan(&method)
	if method != "scan_verified" {
		t.Fatalf("resolution_method %q, want scan_verified", method)
	}
}

// A run under another scan profile (another config, a narrower ruleset) does
// not prove the check that found the finding ran again. A finding re-seen
// under the new profile can then be closed by it.
func TestRepoAutoResolve_ProfileChangeNeverCloses(t *testing.T) {
	rr := newRepoRun(t)
	wide := rr.r.scanProfile(rr.tn, "p-default")
	narrow := rr.r.scanProfile(rr.tn, "p-owasp")
	rr.baseline(wide)

	cmd := rr.r.runCommand(rr.tn, "semgrep", narrow, "completed", 0)
	if st := rr.send(cmd, "a"); st.AutoResolved != 0 {
		t.Fatalf("narrower profile resolved: %+v", st)
	}
	if got := rr.goneStatus(); got == "resolved" {
		t.Fatal("a run under another profile closed a finding it never checked")
	}

	// Under the narrow profile: seen once, then missing -> closed.
	cmd = rr.r.runCommand(rr.tn, "semgrep", narrow, "completed", 0)
	rr.send(cmd, "a", "gone")
	cmd = rr.r.runCommand(rr.tn, "semgrep", narrow, "completed", 0)
	if st := rr.send(cmd, "a"); st.AutoResolve != protov2.AutoResolveApplied || st.AutoResolved != 1 {
		t.Fatalf("same profile: %+v", st)
	}
	if got := rr.goneStatus(); got != "resolved" {
		t.Fatalf("status %q, want resolved", got)
	}
}

// A tenant upload (server-side ingest) or a protocol v1 report that claims
// coverage_type full on the default branch never closes a finding, however
// many it leaves out (owner decision O11).
func TestRepoAutoResolve_UploadsAndV1NeverClose(t *testing.T) {
	rr := newRepoRun(t)
	tid := rr.tn.tenant
	report := func(rules ...string) *ctis.Report {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), CoverageType: "full",
				Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, RepositoryURL: "https://" + rr.tn.repo}},
			Assets: []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: rr.tn.repo}}}
		for _, rule := range rules {
			rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding " + rule,
				Severity: ctis.SeverityHigh, RuleID: rule, AssetRef: "repo",
				Location: &ctis.FindingLocation{Path: "src/" + rule + ".go", StartLine: 10}})
		}
		return rep
	}
	// The tenant accepts reports without a command (warn mode), so the v1
	// report is applied: the point is that it still closes nothing.
	p := sensorresult.Policy{TenantID: tid, Mode: sensorresult.ModeWarn}
	if err := rr.results.SavePolicy(context.Background(), &p); err != nil {
		t.Fatal(err)
	}
	v1 := &sensor.Sensor{ID: rr.tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmd := rr.r.runCommand(rr.tn, "semgrep", "", "completed", 0)
	cases := []struct {
		name string
		agt  *sensor.Sensor
		opts ingest.Options
	}{
		{"tenant upload", &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}, ingest.Options{}},
		{"v1 sensor without a command", v1, ingest.Options{}},
		{"v1 sensor bound to a completed command", v1, ingest.Options{Binding: ingest.Binding{
			Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"https://" + rr.tn.repo + ".git"}, Tool: "semgrep"}}},
	}
	for _, tc := range cases {
		name, agt := tc.name, tc.agt
		if _, err := rr.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: report("a", "gone"), CoverageType: ingest.CoverageTypeFull, Options: tc.opts}); err != nil {
			t.Fatalf("%s baseline: %v", name, err)
		}
		out, err := rr.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: report("a"), CoverageType: ingest.CoverageTypeFull, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out.FindingsAutoResolved != 0 || rr.goneStatus() == "resolved" {
			t.Fatalf("%s with coverage full closed a finding (auto-resolved %d)", name, out.FindingsAutoResolved)
		}
	}
}

// The good path: a clean bound run of the same tool and profile closes what
// it no longer reports.
func TestRepoAutoResolve_CleanBoundRunCloses(t *testing.T) {
	rr := newRepoRun(t)
	p := rr.r.scanProfile(rr.tn, "p-default")
	rr.baseline(p)
	cmd := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	if st := rr.send(cmd, "a"); st.AutoResolve != protov2.AutoResolveApplied || st.AutoResolved != 1 {
		t.Fatalf("clean run: %+v", st)
	}
	if got := rr.goneStatus(); got != "resolved" {
		t.Fatalf("status %q, want resolved", got)
	}
}
