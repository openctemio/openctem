package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// The CI runner sends each capability's state with the verdict request. A
// capability that failed, uploaded only partial results, was not uploaded or
// is missing fails the gate with a reason naming it, even when the job's
// scan_failures count says zero (a modified job, or one that counted wrong):
// a gate never passes on results that did not reach the platform.
func TestCIGateFailsOnCapabilityStates(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"
	low := ciFinding("Low", "go.low", "low", ctis.FindingTypeVulnerability, "a.go", 1)

	n := 0
	evaluate := func(caps []map[string]string) map[string]any {
		t.Helper()
		n++
		sha := strings.Repeat(fmt.Sprintf("%x", n%16), 40)
		resp, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", "feature/x", sha, map[string]any{"job_id": fmt.Sprint(n)})})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("exchange: %d %v", resp.StatusCode, ex)
		}
		id, tok := ex["run_id"].(string), ex["token"].(string)
		if resp, up := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, low)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, up)
		}
		resp, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, map[string]any{"scan_failures": 0, "capabilities": caps})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return v
	}

	// Every capability uploaded: judged on the findings (a low one passes).
	if v := evaluate([]map[string]string{{"name": "sast", "tool": "opengrep", "state": "uploaded"},
		{"name": "secrets", "tool": "gitleaks", "state": " Uploaded "}}); v["verdict"] != "pass" || hasReason(v, cirun.ReasonCapabilityFailed) {
		t.Fatalf("all uploaded: %v", v)
	}
	// Each state that is not clean fails, scan_failures 0 notwithstanding.
	for _, state := range []string{"failed", "partial", "not_uploaded", "missing", "something_new", ""} {
		v := evaluate([]map[string]string{{"name": "sast", "tool": "opengrep", "state": "uploaded"},
			{"name": "secrets", "tool": "gitleaks", "state": state, "reason": "http_413"}})
		if v["verdict"] != "fail" || !hasReason(v, cirun.ReasonCapabilityFailed) {
			t.Fatalf("state %q: %v", state, v)
		}
	}
	// No capabilities sent (an older runner): judged as before.
	if v := evaluate(nil); v["verdict"] != "pass" {
		t.Fatalf("older runner: %v", v)
	}
}
