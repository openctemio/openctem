package integration

// Known false positives in CI: a decision made on the platform (false
// positive, accepted risk, an approved exception) holds on the next run of the
// same repository. The gate does not count the finding, the upload tells the
// job which of its own results are decided so it can leave them out of its
// console, SARIF and merge request report, and a material change to the
// flagged code makes it a new finding that is judged again.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func sastWithCode(title, rule, path string, line int, code string) ctis.Finding {
	f := ciFinding(title, rule, "high", ctis.FindingTypeVulnerability, path, line)
	f.Location.Snippet = code
	return f
}

func knownIndexes(t *testing.T, out map[string]any) map[int]string {
	t.Helper()
	raw, ok := out["known"].([]any)
	if !ok {
		t.Fatalf("upload response has no known list: %v", out)
	}
	got := map[int]string{}
	for _, k := range raw {
		m := k.(map[string]any)
		if m["finding_id"] == "" {
			t.Fatalf("known entry without a finding id: %v", m)
		}
		got[int(m["index"].(float64))] = m["decision"].(string)
	}
	return got
}

func knownCount(t *testing.T, out map[string]any) int { return len(knownIndexes(t, out)) }

func TestCIKnownFindings_DecisionsHoldOnTheNextRun(t *testing.T) {
	r := newCIRig(t)
	r.svc.SetSuppressionRules(suppression.NewService(postgres.NewSuppressionRepository(r.db), logger.NewNop()), nil)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	run := func(tenant string, aud, ref, sha, job string, policy map[string]any, findings ...ctis.Finding) (map[string]any, map[string]any) {
		t.Helper()
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": tenant,
			"id_token": r.idp.token(t, aud, "acme/api", ref, sha, map[string]any{"job_id": job})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		if id == "" {
			t.Fatalf("exchange: %v", ex)
		}
		resp, up := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, findings...))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, up)
		}
		body := map[string]any{}
		if policy != nil {
			body["repo_policy"] = policy
		}
		resp, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("evaluate: %d %v", resp.StatusCode, v)
		}
		return up, v
	}
	summary := func(v map[string]any) (accepted, blocking int) {
		s := v["summary"].(map[string]any)
		return int(s["accepted"].(float64)), int(s["blocking"].(float64))
	}
	blocks := func(v map[string]any, rule string) bool {
		for _, x := range v["reasons"].([]any) {
			m := x.(map[string]any)
			if m["rule_id"] == rule && m["mode"] == nil {
				return true
			}
		}
		return false
	}

	cmdi := sastWithCode("Command injection", "py.cmdi", "app/run.py", 10, "    os.system(cmd)")
	md5 := sastWithCode("Weak hash", "py.md5", "app/hash.py", 4, "hashlib.md5(data)")

	// 1. The default branch reports both: its first run records them as the
	// gate baseline and passes.
	if _, v := run(r.tenant.String(), cfg.Audience, "main", strings.Repeat("1", 40), "1", nil, cmdi, md5); v["verdict"] != "pass" ||
		!hasReason(v, cirun.ReasonBaselineEstablished) {
		t.Fatalf("baseline verdict: %v", v)
	}

	// 2. AppSec marks the command injection a false positive (the console's
	// approval sets this status), and the developer asks for an exception for
	// the weak hash in .openctem.yml, which AppSec approves.
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive', resolution = 'false_positive'
		WHERE tenant_id = $1 AND rule_id = 'py.cmdi'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	exception := []map[string]string{{"rule_id": "py.md5", "path": "app/hash.py", "reason": "checksum of public files, not security", "expires": expiresSoon()}}
	run(r.tenant.String(), cfg.Audience, "main", strings.Repeat("2", 40), "2", map[string]any{"exceptions": exception}, cmdi, md5)
	if _, err := r.db.ExecContext(ctx, `UPDATE suppression_rules SET status = 'approved', approved_at = NOW()
		WHERE tenant_id = $1 AND rule_id = 'py.md5' AND status = 'pending'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}

	// 3. Next pull request: code was inserted above the flagged line (line
	// shift) and a new issue appears. The decided results are known to the
	// job and not counted; the false positive stays one.
	moved := cmdi
	moved.Location = &ctis.FindingLocation{Path: "app/run.py", StartLine: 25, Snippet: "\tos.system(cmd)"}
	sqli := sastWithCode("SQL injection", "py.sqli", "app/db.py", 7, "cur.execute(q % x)")
	up, v := run(r.tenant.String(), cfg.Audience, "feature/a", strings.Repeat("3", 40), "3", nil, moved, md5, sqli)
	known := knownIndexes(t, up)
	if len(known) != 2 || known[0] != cirun.DecisionFalsePositive || known[1] != cirun.DecisionSuppressed {
		t.Fatalf("known = %v, want index 0 false_positive and 1 suppressed (the exception covers a finding that existed before it)", known)
	}
	acc, blk := summary(v)
	if acc != 2 || blk != 1 || blocks(v, "py.cmdi") || blocks(v, "py.md5") || !blocks(v, "py.sqli") {
		t.Fatalf("pull request verdict: accepted %d blocking %d %v", acc, blk, v["reasons"])
	}
	var status string
	if err := r.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = 'py.cmdi'`,
		r.tenant.String()).Scan(&status); err != nil || status != "false_positive" {
		t.Fatalf("the false positive became %q (%v)", status, err)
	}

	// 4. The flagged code changes materially: it is a new finding, judged
	// again, not hidden.
	edited := cmdi
	edited.Location = &ctis.FindingLocation{Path: "app/run.py", StartLine: 25, Snippet: "os.system(request.args['cmd'])"}
	up, v = run(r.tenant.String(), cfg.Audience, "feature/b", strings.Repeat("4", 40), "4", nil, edited)
	if k := knownIndexes(t, up); len(k) != 0 {
		t.Fatalf("a materially changed finding is reported as known: %v", k)
	}
	if !blocks(v, "py.cmdi") {
		t.Fatalf("the changed code did not block: %v", v["reasons"])
	}

	// 5. Another tenant reporting the same results learns nothing about this
	// tenant's decisions.
	ocfg := r.trust(r.other, cirun.Rules{Owners: []string{"acme"}})
	up, _ = run(r.other.String(), ocfg.Audience, "main", strings.Repeat("5", 40), "5", nil, cmdi, md5)
	if k := knownIndexes(t, up); len(k) != 0 {
		t.Fatalf("another tenant's decisions leaked: %v", k)
	}

	// 6. An exception that expired no longer hides or passes the finding.
	if _, err := r.db.ExecContext(ctx, `UPDATE suppression_rules SET expires_at = NOW() - interval '1 minute'
		WHERE tenant_id = $1 AND rule_id = 'py.md5'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	up, v = run(r.tenant.String(), cfg.Audience, "feature/c", strings.Repeat("6", 40), "6", nil, md5)
	// (It is pre-existing on the default branch, so the default policy, new
	// findings only, lists it as pre-existing rather than accepted.)
	if acc, _ := summary(v); acc != 0 || knownCount(t, up) != 0 {
		t.Fatalf("expired exception still honored: accepted %d known %v", acc, up["known"])
	}
}
