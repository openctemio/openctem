package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A repository's .openctem.yml only tightens the gate; its exceptions become
// pending suppression requests once, from the default branch only; a policy
// can forbid the file; an invalid file is refused (RFC-077 G-8).
func TestCIRepositoryPolicyFile(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"
	const sha = "7777777777777777777777777777777777777777"
	medium := ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)

	run := func(ref, job string, policy map[string]any) (int, map[string]any) {
		t.Helper()
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", ref, sha, map[string]any{"job_id": job})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		if resp, out := r.upload(id, tok, ciReport(repoName, medium)); resp.StatusCode != http.StatusAccepted {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		body := map[string]any{}
		if policy != nil {
			body["repo_policy"] = policy
		}
		resp, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, body)
		return resp.StatusCode, v
	}
	pending := func() int {
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM suppression_rules WHERE tenant_id = $1 AND status = 'pending'
			AND rule_id = 'go.weak-hash'`, r.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exception := []map[string]string{{"rule_id": "go.weak-hash", "path": "hash.go", "reason": "migrating to sha256 this quarter",
		"expires": "2099-01-01"}}

	// Without the file a medium finding passes the default policy (high).
	if code, v := run("main", "1", nil); code != http.StatusOK || v["verdict"] != "pass" {
		t.Fatalf("no file: %d %v", code, v)
	}
	// The file lowers the threshold and judges every finding: it fails, and
	// says the file applied.
	if code, v := run("feature/x", "2", map[string]any{"fail_on_severity": "medium", "new_findings_only": false}); code != http.StatusOK ||
		v["verdict"] != "fail" || v["repo_file"] != "applied" {
		t.Fatalf("tightened: %d %v", code, v)
	}
	// A looser value loosens nothing: still new-findings-only at high, the
	// pre-existing medium passes exactly as without a file.
	if code, v := run("feature/y", "3", map[string]any{"fail_on_severity": "critical", "new_findings_only": true}); code != http.StatusOK ||
		v["verdict"] != "pass" {
		t.Fatalf("looser file: %d %v", code, v)
	}
	// Exceptions from a branch are not requested; from the default branch once.
	exception[0]["expires"] = expiresSoon()
	run("feature/z", "5", map[string]any{"exceptions": exception})
	if pending() != 0 {
		t.Fatal("a branch run requested an exception")
	}
	if code, v := run("main", "6", map[string]any{"exceptions": exception}); code != http.StatusOK {
		t.Fatalf("default branch with exceptions: %d %v", code, v)
	}
	run("main", "7", map[string]any{"exceptions": exception})
	if n := pending(); n != 1 {
		t.Fatalf("pending requests = %d, want 1", n)
	}
	if r.auditCount(r.tenant, "ci_run.exceptions_requested", "requested") != 1 {
		t.Fatal("exception request not audited")
	}
	// An invalid file is refused, not ignored.
	if code, _ := run("feature/w", "8", map[string]any{"fail_on_severity": "nope"}); code != http.StatusBadRequest {
		t.Fatalf("invalid file: %d", code)
	}
	// A policy that forbids repository files: the file is ignored.
	no := false
	if _, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeTenant, AllowRepoPolicy: &no},
		cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if code, v := run("feature/v", "9", map[string]any{"fail_on_severity": "medium", "new_findings_only": false}); code != http.StatusOK ||
		v["verdict"] != "pass" || v["repo_file"] != "ignored" {
		t.Fatalf("forbidden file: %d %v", code, v)
	}
}

// expiresSoon is a date within the 90-day exception window.
func expiresSoon() string { return time.Now().AddDate(0, 0, 30).Format("2006-01-02") }
