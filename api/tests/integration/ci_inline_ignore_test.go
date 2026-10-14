package integration

// Inline ignore comments and scanner ignore files are the author's claim:
// the gate still counts such results, and from a verified default-branch run
// each becomes a pending suppression request named after the CI identity,
// audited. A branch run requests nothing.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCIInlineIgnores_BecomePendingRequests(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	ignored := ciFinding("Command injection", "py.cmdi", "high", ctis.FindingTypeVulnerability, "app/run.py", 4)
	ignored.Location.Snippet = "os.system(cmd)  # nosemgrep"
	ignored.Suppression = &ctis.Suppression{Kind: "in_source", Status: "accepted", Justification: "nosemgrep"}

	run := func(ref, job string) map[string]any {
		t.Helper()
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, "acme/api", ref, strings.Repeat(job, 40), map[string]any{"job_id": job})})
		id, tok := ex["run_id"].(string), ex["token"].(string)
		rep := ctis.Report{Version: "1.0",
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), SourceType: "scanner",
				Properties: ctis.Properties{"ignore_file_paths": []any{"generated/**", "legacy/"}}},
			Tool:     &ctis.Tool{Name: "semgrep"},
			Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: repoName}},
			Findings: []ctis.Finding{ignored}}
		if resp, out := r.post("/api/v1/ci/runs/"+id+"/results", tok, map[string]any{"report": rep}); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
		_, v := r.post("/api/v1/ci/runs/"+id+"/evaluate", tok, nil)
		return v
	}
	pending := func() (n int, actors string) {
		_ = r.db.QueryRowContext(ctx, `SELECT count(*), COALESCE(string_agg(DISTINCT requested_by_actor, ','), '') FROM suppression_rules
			WHERE tenant_id = $1 AND status = 'pending'`, r.tenant.String()).Scan(&n, &actors)
		return
	}

	// A branch run: counted, nothing requested.
	v := run("feature/x", "1")
	if s := v["summary"].(map[string]any); s["accepted"].(float64) != 0 {
		t.Fatalf("an inline ignore was honored: %v", s)
	}
	if n, _ := pending(); n != 0 {
		t.Fatalf("a branch run requested %d suppressions", n)
	}

	// The default branch: still counted (it blocks), and three requests
	// (the inline rule+path, two ignore-file paths) named after the CI job.
	v = run("main", "2")
	if v["verdict"] != "fail" {
		t.Fatalf("the ignored high finding did not block the default branch: %v", v)
	}
	n, actors := pending()
	if n != 3 || !strings.HasPrefix(actors, "ci:") {
		t.Fatalf("pending = %d by %q, want 3 by the CI identity", n, actors)
	}
	var audits int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM suppression_rule_audit a JOIN suppression_rules s ON s.id = a.suppression_rule_id
		WHERE s.tenant_id = $1 AND a.action = 'created' AND a.details->>'requested_by_actor' LIKE 'ci:%'`, r.tenant.String()).Scan(&audits)
	if audits != 3 {
		t.Fatalf("audit rows = %d, want 3", audits)
	}
	var pathOnly int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM suppression_rules WHERE tenant_id = $1 AND rule_id IS NULL AND path_pattern = 'generated/**'`,
		r.tenant.String()).Scan(&pathOnly)
	if pathOnly != 1 {
		t.Fatal("the ignore-file path was not requested as a path rule")
	}
	// Again: no duplicates.
	run("main", "3")
	if n, _ := pending(); n != 3 {
		t.Fatalf("pending = %d after a second run, want 3", n)
	}
	// Another tenant sees none of them.
	var other int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM suppression_rules WHERE tenant_id = $1`, r.other.String()).Scan(&other)
	if other != 0 {
		t.Fatal("requests leaked into another tenant")
	}
}
