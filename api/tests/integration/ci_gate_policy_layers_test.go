package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Per-repository gate settings (docs/rfcs/RFC-096-ci-per-repository-settings.md):
// a repository policy sets only some fields and inherits the rest; an
// organization lock is a floor no one can loosen below; loosening an
// unlocked field needs a reason and step-up; an expired override stops
// applying; the repository file never loosens. Every verdict is computed
// from the policies stored at evaluation time.
func TestCIGatePolicyLayers(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/layers"
	const sha = "8888888888888888888888888888888888888888"
	medium := ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)
	admin := cirunapp.Actor{Email: "admin@acme.test"}

	job := 0
	runID := ""
	evaluate := func(policy map[string]any) map[string]any {
		t.Helper()
		job++
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/layers", "feature/x", sha, map[string]any{"job_id": strings.Repeat("j", job)})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		runID = id
		if resp, out := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, medium)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		body := map[string]any{}
		if policy != nil {
			body["repo_policy"] = policy
		}
		resp, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}

	// The organization fails every medium finding and locks the severity.
	no := false
	locked := []string{cirun.FieldFailOnSeverity}
	org, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant,
		FailOnSeverity: "medium", NewFindingsOnly: &no}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if v := evaluate(nil); v["verdict"] != "fail" {
		t.Fatalf("org policy: %v", v)
	}
	run, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(runID))
	if err != nil {
		t.Fatal(err)
	}
	repoID := run.RepositoryAssetID

	// Before the lock, a looser repository severity is allowed with a
	// reason and step-up; it inherits every other field (new findings only
	// stays off, so the run is judged on every finding).
	sev := []string{cirun.FieldFailOnSeverity}
	repoPol, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository,
		ScopeID: &repoID, FailOnSeverity: "critical", Fields: &sev, Reason: "legacy service, retiring this quarter"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if v := evaluate(nil); v["verdict"] != "pass" {
		t.Fatalf("repository override: %v", v)
	}
	res, err := r.svc.ResolveRepositoryPolicy(ctx, r.tenant, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Field(cirun.FieldFailOnSeverity).Source != cirun.ScopeRepository || res.Field(cirun.FieldNewFindingsOnly).Source != cirun.ScopeTenant ||
		res.Policy.NewFindingsOnly {
		t.Fatalf("provenance: %+v", res.Fields)
	}

	// Lock: the organization locks the severity. The existing looser
	// override is ignored at evaluation, and a new looser value is refused
	// whatever the caller's permission and sign-in.
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{LockedFields: &locked,
		NewFindingsOnly: &no}, admin); err != nil {
		t.Fatal(err)
	}
	if v := evaluate(nil); v["verdict"] != "fail" {
		t.Fatalf("locked field still loosened by the repository: %v", v)
	}
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, cirunapp.GatePolicyInput{FailOnSeverity: "high", Fields: &sev,
		Reason: "still legacy, still retiring"}, admin); !errors.Is(err, cirun.ErrFieldLocked) {
		t.Fatalf("loosening a locked field: %v", err)
	}

	// Tighten: a stricter value of the locked field needs neither a reason
	// nor step-up.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, cirunapp.GatePolicyInput{FailOnSeverity: "low", Fields: &sev}, admin); err != nil {
		t.Fatalf("tightening a locked field: %v", err)
	}
	// Removing the organization's lock loosens: step-up.
	none := []string{}
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{LockedFields: &none, NewFindingsOnly: &no}, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("lock removal without step-up: %v", err)
	}

	// Loosen with permission: warn mode on this repository (unlocked) needs
	// a reason, then step-up; with both it applies.
	modeSev := []string{cirun.FieldMode, cirun.FieldFailOnSeverity}
	warn := cirunapp.GatePolicyInput{Mode: cirun.ModeWarn, FailOnSeverity: "low", Fields: &modeSev}
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, warn, admin); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("loosening without a reason: %v", err)
	}
	warn.Reason = "pilot repository, warn only"
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	warn.ExpiresAt = &expires
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, warn, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("loosening without step-up: %v", err)
	}
	r.svc.SetStepUpGate(recentAuth{})
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, warn, admin); err != nil {
		t.Fatal(err)
	}
	if v := evaluate(nil); v["verdict"] != "pass" || v["would_fail"] != true {
		t.Fatalf("warn override: %v", v)
	}
	if r.auditCount(r.tenant, "ci_gate_policy.loosened", "mode") < 1 {
		t.Fatal("loosening not audited")
	}
	// The pipelines list filters on repositories with their own policy,
	// tenant-scoped.
	if ps, err := r.repo.ListPipelines(ctx, r.tenant, cirun.PipelineFilter{HasPolicyOverride: true}); err != nil || len(ps) != 1 ||
		ps[0].RepositoryAssetID != repoID {
		t.Fatalf("has_policy_override: %d %v", len(ps), err)
	}
	if ps, _ := r.repo.ListPipelines(ctx, r.other, cirun.PipelineFilter{HasPolicyOverride: true}); len(ps) != 0 {
		t.Fatal("another tenant listed the pipeline")
	}
	// Dropping the end of a looser override loosens too.
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	noEnd := warn
	noEnd.ExpiresAt = nil
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, repoPol.ID, noEnd, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("removing the expiry without step-up: %v", err)
	}
	r.svc.SetStepUpGate(recentAuth{})

	// The repository file cannot loosen the resolved policy: with the
	// override in warn mode it cannot turn the would-fail into nothing, and
	// with enforce it cannot pass a medium finding.
	if v := evaluate(map[string]any{"fail_on_severity": "critical", "new_findings_only": true}); v["would_fail"] != true {
		t.Fatalf("repository file loosened a warn verdict: %v", v)
	}

	// Expired override: once its end has passed it stops applying, and the
	// gate enforces the organization's policy again.
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_gate_policies SET expires_at = now() - interval '1 minute'
		WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), repoPol.ID.String()); err != nil {
		t.Fatal(err)
	}
	if v := evaluate(nil); v["verdict"] != "fail" {
		t.Fatalf("expired override still applied: %v", v)
	}
	if v := evaluate(map[string]any{"fail_on_severity": "critical", "new_findings_only": true}); v["verdict"] != "fail" ||
		v["repo_file"] != "applied" {
		t.Fatalf("repository file loosened the gate: %v", v)
	}
	if res, _ := r.svc.ResolveRepositoryPolicy(ctx, r.tenant, repoID); !res.RepositoryExpired || res.Source != cirun.ScopeTenant {
		t.Fatalf("expired provenance: %+v", res)
	}
	if ps, _ := r.repo.ListPipelines(ctx, r.tenant, cirun.PipelineFilter{HasPolicyOverride: true}); len(ps) != 0 {
		t.Fatal("an expired override still counts as an override")
	}

	// Tenant isolation: another tenant's policies never reach this
	// repository, and it cannot write one for it.
	if _, err := r.svc.CreateGatePolicy(ctx, r.other, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository,
		ScopeID: &repoID, Fields: &sev, FailOnSeverity: "low"}, admin); err == nil {
		t.Fatal("policy on another tenant's repository accepted")
	}
	if _, err := r.svc.CreateGatePolicy(ctx, r.other, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, Mode: cirun.ModeWarn}, admin); err != nil {
		t.Fatal(err)
	}
	if res, _ := r.svc.ResolveRepositoryPolicy(ctx, r.tenant, repoID); res.Policy.Mode != cirun.ModeEnforce {
		t.Fatal("another tenant's policy applied")
	}
	if res, _ := r.svc.ResolveRepositoryPolicy(ctx, r.other, repoID); res.Repository != nil {
		t.Fatal("another tenant resolved this repository's policy")
	}
}

// A repository policy cannot lock fields and cannot carry an end beyond a
// year; the organization policy always sets every field.
func TestCIGatePolicyLayers_Validation(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	admin := cirunapp.Actor{Email: "admin@acme.test"}
	some := []string{cirun.FieldMode}
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, Fields: &some}, admin); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("partial organization policy: %v", err)
	}
	unknown := []string{"nope"}
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, LockedFields: &unknown}, admin); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown lock: %v", err)
	}
	far := time.Now().AddDate(2, 0, 0)
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, ExpiresAt: &far}, admin); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("organization expiry: %v", err)
	}
}

// The gate baseline settings of the layered policy: the first-run baseline
// can be turned off, a grace ends the baseline's debt exemption (its due
// date), and secrets in the baseline block unless the organization says
// otherwise.
func TestCIGatePolicyLayers_BaselineSettings(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/graced"
	const sha = "6666666666666666666666666666666666666666"
	high := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)
	secret := ciFinding("AWS key", "aws-key", "high", ctis.FindingTypeSecret, "cfg.go", 3)
	admin := cirunapp.Actor{Email: "admin@acme.test"}
	job := 0
	lastRun := ""
	run := func(fs ...ctis.Finding) map[string]any {
		t.Helper()
		job++
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/graced", "main", sha, map[string]any{"job_id": strings.Repeat("g", job)})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		lastRun = id
		if resp, out := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, fs...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		_, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, map[string]any{})
		return v
	}

	// First-run baseline off: the first default-branch run judges every
	// finding as new.
	off, grace := false, 1
	org, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, BaselineOnFirstRun: &off}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if v := run(high); v["verdict"] != "fail" || hasReason(v, cirun.ReasonBaselineEstablished) {
		t.Fatalf("first run with the first-run baseline off: %v", v)
	}
	first, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(lastRun))
	if err != nil {
		t.Fatal(err)
	}
	repoID := first.RepositoryAssetID
	if _, err := r.svc.SetGateBaseline(ctx, r.tenant, repoID, admin); err != nil {
		t.Fatal(err)
	}
	if v := run(high); v["verdict"] != "pass" {
		t.Fatalf("manual baseline: %v", v)
	}
	// A one-day grace: the verdict names the due date; once it has passed
	// the baseline's debt blocks again.
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{BaselineOnFirstRun: &off, BaselineGraceDays: &grace}, admin); err != nil {
		t.Fatal(err)
	}
	if v := run(high); v["verdict"] != "pass" || v["baseline"].(map[string]any)["due_at"] == nil {
		t.Fatalf("within the grace: %v", v)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_gate_baselines SET set_at = now() - interval '2 days'
		WHERE tenant_id = $1 AND repository_asset_id = $2`, r.tenant.String(), repoID.String()); err != nil {
		t.Fatal(err)
	}
	if v := run(high); v["verdict"] != "fail" {
		t.Fatalf("after the grace: %v", v)
	}
	// Secrets in the baseline block by default; turning that off (loosening:
	// step-up) lists them without blocking.
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{BaselineOnFirstRun: &off}, admin); err != nil {
		t.Fatal(err)
	}
	run(secret)
	if _, err := r.svc.SetGateBaseline(ctx, r.tenant, repoID, admin); err != nil {
		t.Fatal(err)
	}
	if v := run(secret); v["verdict"] != "fail" || !hasReason(v, cirun.ReasonSecret) {
		t.Fatalf("baseline secret did not block: %v", v)
	}
	r.svc.SetStepUpGate(recentAuth{err: errNeedsStepUp})
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{BaselineOnFirstRun: &off, BaselineSecretsBlock: &off}, admin); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("secrets off without step-up: %v", err)
	}
	r.svc.SetStepUpGate(recentAuth{})
	if _, err := r.svc.UpdateGatePolicy(ctx, r.tenant, org.ID, cirunapp.GatePolicyInput{BaselineOnFirstRun: &off, BaselineSecretsBlock: &off}, admin); err != nil {
		t.Fatal(err)
	}
	if v := run(secret); v["verdict"] != "pass" || !hasReason(v, cirun.ReasonSecretPreExisting) {
		t.Fatalf("baseline secret with secrets off: %v", v)
	}
}

// The first-run baseline is announced to the administrators once, like a
// baseline recorded by hand.
func TestCIGateBaseline_FirstRunIsAnnounced(t *testing.T) {
	alerts := &alertRecorder{}
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example"}, func(d *cirunapp.Deps) { d.Alerts = alerts })
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/announced"
	const sha = "6666666666666666666666666666666666666661"
	run := func(job string) map[string]any {
		t.Helper()
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/announced", "main", sha, map[string]any{"job_id": job})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, ciFinding("SQLi", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 7)))
		_, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, map[string]any{})
		return v
	}
	count := func() int {
		n := 0
		for _, a := range alerts.got {
			if a.Metadata["action"] == "baseline_established" {
				n++
			}
		}
		return n
	}
	if v := run("1"); v["verdict"] != "pass" || count() != 1 {
		t.Fatalf("first run: %v, %d announcements", v, count())
	}
	if run("2"); count() != 1 {
		t.Fatalf("announced again: %d", count())
	}
}
