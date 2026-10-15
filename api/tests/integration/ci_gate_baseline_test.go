package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A failed default-branch run must never become the comparison base: running
// it again (or pushing again) used to turn every finding of the first run
// into "already on the default branch" and pass. A default-branch run is
// judged against the repository's gate baseline only, which a person with
// the policy permission records (step-up, audited high); pull requests
// compare with the target branch and, once a baseline exists, only its
// findings are pre-existing.
func TestCIGateBaseline_DefaultBranchRerunCannotWhitewash(t *testing.T) {
	alerts := &alertRecorder{}
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example"}, func(d *cirunapp.Deps) { d.Alerts = alerts })
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/rerun"
	const sha = "9999999999999999999999999999999999999999"
	legacy := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 12)
	fresh := ciFinding("Command injection", "go.cmdi", "high", ctis.FindingTypeVulnerability, "run.go", 7)
	admin := cirunapp.Actor{Email: "admin@acme.test"}

	job := 0
	lastRun := ""
	run := func(ref string, findings ...ctis.Finding) map[string]any {
		t.Helper()
		job++
		claims := map[string]any{"job_id": strings.Repeat("r", job)}
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/rerun", ref, sha, claims)})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		lastRun = id
		if resp, out := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, findings...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		resp, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, map[string]any{})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}
	summary := func(v map[string]any) (int, int, int) {
		s, _ := v["summary"].(map[string]any)
		n := func(k string) int { f, _ := s[k].(float64); return int(f) }
		return n("new"), n("pre_existing"), n("blocking")
	}

	// First default-branch run: it records the repository's gate baseline
	// (once per repository) and passes, saying so.
	v := run("main", legacy)
	if nw, pre, _ := summary(v); v["verdict"] != "pass" || nw != 0 || pre != 1 || !hasReason(v, cirun.ReasonBaselineEstablished) {
		t.Fatalf("first run: %v", v)
	}
	if bl, _ := v["baseline"].(map[string]any); bl["established"] != true || bl["set_at"] == nil {
		t.Fatalf("verdict does not name the new baseline: %v", v)
	}
	run1, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(lastRun))
	if err != nil {
		t.Fatal(err)
	}
	repoID := run1.RepositoryAssetID
	b, err := r.svc.GetGateBaseline(ctx, r.tenant, repoID)
	if err != nil || b.Source != cirun.BaselineSourceFirstRun || b.FindingsCount != 1 || b.Branch != "main" {
		t.Fatalf("first-run baseline %+v %v", b, err)
	}
	if r.auditCount(r.tenant, "ci_gate_baseline.set", "first_run") != 1 {
		t.Fatal("first-run baseline not audited")
	}
	// The rerun is judged against the same baseline, not established again.
	v = run("main", legacy)
	if _, pre, _ := summary(v); v["verdict"] != "pass" || pre != 1 || hasReason(v, cirun.ReasonBaselineEstablished) {
		t.Fatalf("rerun: %v", v)
	}

	// A finding added after the baseline blocks, on every rerun.
	for i := 0; i < 2; i++ {
		v = run("main", legacy, fresh)
		if nw, pre, blocking := summary(v); v["verdict"] != "fail" || nw != 1 || pre != 1 || blocking != 1 {
			t.Fatalf("post-baseline finding, run %d: %v", i, v)
		}
	}
	// A pull request: the legacy finding (baseline) is pre-existing; the
	// post-baseline finding is open on main from the failed runs above but
	// is not in the baseline, so it still blocks the pull request.
	v = run("feature/x", legacy, fresh)
	if nw, pre, _ := summary(v); v["verdict"] != "fail" || nw != 1 || pre != 1 {
		t.Fatalf("pull request compared with failed default-branch runs: %v", v)
	}

	// Recording a new baseline by hand needs step-up; it takes in the
	// post-baseline finding, audited high and announced.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	if _, err := r.svc.SetGateBaseline(ctx, r.tenant, repoID, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("baseline without step-up: %v", err)
	}
	r.svc.SetStepUpGate(recentAuth{})
	alertsBefore := alerts.count()
	if b, err = r.svc.SetGateBaseline(ctx, r.tenant, repoID, admin); err != nil || b.FindingsCount != 2 || b.Source != cirun.BaselineSourceManual {
		t.Fatalf("manual baseline %+v %v", b, err)
	}
	if n := r.auditCount(r.tenant, "ci_gate_baseline.set", ""); n != 2 {
		t.Fatalf("baseline audited %d times", n)
	}
	if alerts.count() != alertsBefore+1 || alerts.got[len(alerts.got)-1].Metadata["action"] != "baseline_set" {
		t.Fatalf("baseline not announced: %+v", alerts.got)
	}
	if v := run("main", legacy, fresh); v["verdict"] != "pass" {
		t.Fatalf("after the manual baseline: %v", v)
	}

	// Tenant isolation: another tenant cannot record or read this
	// repository's baseline.
	if _, err := r.svc.SetGateBaseline(ctx, r.other, repoID, admin); err == nil {
		t.Fatal("another tenant recorded the baseline")
	}
	if _, err := r.svc.GetGateBaseline(ctx, r.other, repoID); !errors.Is(err, cirun.ErrBaselineNotFound) {
		t.Fatalf("another tenant read the baseline: %v", err)
	}
	if err := r.svc.DeleteGateBaseline(ctx, r.other, repoID, admin); !errors.Is(err, cirun.ErrBaselineNotFound) {
		t.Fatalf("another tenant removed the baseline: %v", err)
	}

	// Removing the baseline (no step-up needed: stricter) makes the legacy
	// finding block the default branch again, and no later run records a
	// first-run baseline again.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	if err := r.svc.DeleteGateBaseline(ctx, r.tenant, repoID, admin); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if v := run("main", legacy); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonNoBaseline) {
			t.Fatalf("after removing the baseline, run %d: %v", i, v)
		}
	}
}

// emptyBaseline gives a repository an empty gate baseline, so that its
// default-branch runs judge every finding as new (no first-run baseline).
func (r *ciRig) emptyBaseline(tenant shared.ID, repoName string) {
	r.t.Helper()
	res, err := r.db.ExecContext(context.Background(), `INSERT INTO ci_gate_baselines (tenant_id, repository_asset_id, source)
		SELECT tenant_id, id, 'manual' FROM assets WHERE tenant_id = $1 AND name = $2`, tenant.String(), repoName)
	if err != nil {
		r.t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		r.t.Fatalf("no repository asset %q", repoName)
	}
}
