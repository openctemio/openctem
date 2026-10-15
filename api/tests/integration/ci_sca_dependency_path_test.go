package integration

// A CI SCA finding says whether its package is a direct dependency and, when
// not, the chain that brings it in (testdata/ci_sca). Through the real upload
// path the finding keeps that, bounded, and a later sighting replaces it.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func ciSCAFixture(t *testing.T, repo string) ctis.Report {
	t.Helper()
	b, err := os.ReadFile("testdata/ci_sca/trivy-npm-trimmed.json")
	if err != nil {
		t.Fatal(err)
	}
	var rep ctis.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	rep.Metadata.ID = shared.NewID().String()
	rep.Assets[0].Value = repo
	return rep
}

func ciSCAUploadReport(t *testing.T, r *ciRig, tenant shared.ID, cfg *cirun.TrustConfig, rep ctis.Report) {
	t.Helper()
	code, ex := r.exchange(tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", "6666666666666666666666666666666666666666", nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	if resp, out := r.post("/api/v1/ci/runs/"+ex["run_id"].(string)+"/results", ex["token"].(string),
		map[string]any{"report": rep}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
}

// findingDependency reads the stored dependency and start line of the
// tenant's finding for a CVE.
func findingDependency(t *testing.T, r *ciRig, tenant shared.ID, cve string) (*vulnerability.DependencyInfo, int) {
	t.Helper()
	var raw []byte
	var line int
	if err := r.db.QueryRowContext(context.Background(), `SELECT COALESCE(metadata, '{}'::jsonb), COALESCE(start_line, 0)
		FROM findings WHERE tenant_id = $1 AND rule_id = $2`, tenant.String(), cve).Scan(&raw, &line); err != nil {
		t.Fatalf("%s: %v", cve, err)
	}
	meta := map[string]any{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return vulnerability.DependencyFromMeta(meta), line
}

func TestCISCAUpload_PersistsDependencyPath(t *testing.T) {
	r := newCIRig(t)
	cfgA := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	cfgB := r.trust(r.other, cirun.Rules{Owners: []string{"acme"}})
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/api"

	ciSCAUploadReport(t, r, r.tenant, cfgA, ciSCAFixture(t, repoName))

	d, line := findingDependency(t, r, r.tenant, "CVE-2024-45590")
	if d == nil || d.Direct || strings.Join(d.Path, " > ") != "express@4.17.1 > body-parser@1.19.0" || line != 34 {
		t.Fatalf("body-parser: %+v line %d, want transitive via express at line 34", d, line)
	}
	if d, _ := findingDependency(t, r, r.tenant, "CVE-2021-23337"); d == nil || !d.Direct {
		t.Fatalf("lodash: %+v, want direct", d)
	}

	// The other tenant's run reports qs as direct with a hostile path: its
	// finding is its own, and the stored chain is bounded.
	other := ciSCAFixture(t, repoName)
	long := make([]string, 0, 100)
	for range 100 {
		long = append(long, "pkg@1\x07")
	}
	for i := range other.Findings {
		if other.Findings[i].RuleID == "CVE-2022-24999" {
			other.Findings[i].Vulnerability.DependencyPath = append([]string{"root@1"}, append(long, "a@1", "qs@6.7.0")...)
		}
	}
	ciSCAUploadReport(t, r, r.other, cfgB, other)
	if d, _ := findingDependency(t, r, r.other, "CVE-2022-24999"); d == nil || strings.Join(d.Path, " > ") != "root@1 > a@1 > qs@6.7.0" {
		t.Fatalf("other tenant's qs: %+v, want control-character ids dropped", d)
	}
	if d, _ := findingDependency(t, r, r.tenant, "CVE-2022-24999"); d == nil || strings.Join(d.Path, " > ") != "express@4.17.1 > qs@6.7.0" {
		t.Fatalf("qs: %+v, changed by another tenant's upload", d)
	}

	// The next run sees qs as a direct dependency: the chain is replaced.
	next := ciSCAFixture(t, repoName)
	for i := range next.Findings {
		if next.Findings[i].RuleID == "CVE-2022-24999" {
			next.Findings[i].Vulnerability.IsDirect = true
			next.Findings[i].Vulnerability.DependencyPath = []string{"qs@6.7.0"}
		}
	}
	ciSCAUploadReport(t, r, r.tenant, cfgA, next)
	if d, _ := findingDependency(t, r, r.tenant, "CVE-2022-24999"); d == nil || !d.Direct {
		t.Fatalf("qs after the next run: %+v, want direct", d)
	}
	if d, _ := findingDependency(t, r, r.tenant, "CVE-2024-45590"); d == nil || d.Direct || len(d.Path) != 2 {
		t.Fatalf("body-parser after the next run: %+v", d)
	}
}
