package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// postRaw posts a tool export as-is with a run token.
func (r *ciRig) postRaw(path, bearer string, body []byte) (int, map[string]any) {
	r.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// osv-scanner results for two lockfiles of the checkout plus one that names
// another repository: the first two land on the run's repository with the
// token's branch; the third is dropped and counted. Another run's token for
// this run id is refused.
const ciOSVExport = `{"results": [
 {"source": {"path": "services/api/go.mod", "type": "lockfile"},
  "packages": [{"package": {"name": "golang.org/x/net", "version": "0.1.0", "ecosystem": "Go"},
    "vulnerabilities": [{"id": "GO-2023-1571", "aliases": ["CVE-2022-41723"], "summary": "HPACK decoder DoS",
      "affected": [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.7.0"}]}]}]}]}]},
 {"source": {"path": "github.com/evil/other/go.mod", "type": "lockfile"},
  "packages": [{"package": {"name": "golang.org/x/text", "version": "0.3.0", "ecosystem": "Go"},
    "vulnerabilities": [{"id": "GO-2022-1059", "aliases": ["CVE-2022-32149"], "summary": "Accept-Language DoS",
      "affected": [{"package": {"name": "golang.org/x/text", "ecosystem": "Go"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.8"}]}]}]}]}]}
]}`

func TestCIRunner_UploadToolExport(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"
	const sha = "3333333333333333333333333333333333333333"
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, runID := ex["token"].(string), ex["run_id"].(string)

	code, out := r.postRaw("/api/v1/ci/runs/"+runID+"/results", token, []byte(ciOSVExport))
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %v", code, out)
	}
	if out["findings_dropped_out_of_scope"] != float64(1) || out["findings_created"] == float64(0) {
		t.Fatalf("response %v", out)
	}
	var n int
	var branch, assetName string
	if err := r.db.QueryRowContext(ctx, `SELECT count(*), max(COALESCE(f.last_seen_branch, '')), max(a.name)
		FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.tenant_id = $1`, r.tenant.String()).Scan(&n, &branch, &assetName); err != nil {
		t.Fatal(err)
	}
	if n == 0 || branch != "main" || assetName != repoName {
		t.Fatalf("findings %d branch %q asset %q (want on %s)", n, branch, assetName, repoName)
	}
	var other int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND (cve_id = 'CVE-2022-32149' OR title ILIKE '%Accept-Language%')`, r.tenant.String()).Scan(&other)
	if other != 0 {
		t.Fatal("the finding of another repository was ingested")
	}

	// Hostile export: refused, nothing written.
	code, _ = r.postRaw("/api/v1/ci/runs/"+runID+"/results", token,
		[]byte(`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&x;</NessusClientData_v2>`))
	if code != http.StatusBadRequest {
		t.Fatalf("xxe: %d", code)
	}

	// A token of this tenant's run cannot post to a run id of another.
	code, _ = r.postRaw("/api/v1/ci/runs/"+shared.NewID().String()+"/results", token, []byte(ciOSVExport))
	if code != http.StatusNotFound && code != http.StatusUnauthorized {
		t.Fatalf("other run id: %d", code)
	}
}
