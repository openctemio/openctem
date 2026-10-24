package integration

// CI results accepted with 202 and applied by the ingest worker
// (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async").

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// asyncRun opens a default-branch run and returns its token and id.
func (r *ciRig) asyncRun(t *testing.T, sha string) (token, runID, repoName string) {
	t.Helper()
	if r.asyncTrust == nil {
		r.asyncTrust = r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	}
	cfg := r.asyncTrust
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName = strings.ToLower(host) + "/acme/api"
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	return ex["token"].(string), ex["run_id"].(string), repoName
}

func (r *ciRig) count(q string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// The upload answers 202 before anything is applied; the raw body is stored
// sealed (never in plaintext), applied by the worker, then deleted.
func TestCIUploadAsync_StoredSealedAppliedThenDeleted(t *testing.T) {
	r := newCIRig(t)
	token, runID, repoName := r.asyncRun(t, strings.Repeat("4", 40))
	marker := ciFinding("Marker-"+shared.NewID().String(), "go.marker", "medium", ctis.FindingTypeVulnerability, "m.go", 1)
	resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, marker))
	if resp.StatusCode != http.StatusAccepted || out["status"] != "queued" || out["upload_id"] == "" {
		t.Fatalf("accept: %d %v", resp.StatusCode, out)
	}
	uid := out["upload_id"].(string)
	if loc := resp.Header.Get("Location"); loc != "/api/v1/ci/runs/"+runID+"/results/"+uid {
		t.Fatalf("Location %q", loc)
	}
	// Nothing applied yet.
	if n := r.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, r.tenant.String()); n != 0 {
		t.Fatalf("%d findings written before the worker ran", n)
	}
	// Stored sealed: the bytes in the table do not carry the report.
	var sealed []byte
	if err := r.db.QueryRowContext(context.Background(), `SELECT sealed FROM ingest_payloads WHERE tenant_id = $1 AND job_id = $2`,
		r.tenant.String(), uid).Scan(&sealed); err != nil {
		t.Fatalf("stored part: %v", err)
	}
	if bytes.Contains(sealed, []byte("Marker-")) || bytes.Contains(sealed, []byte("semgrep")) {
		t.Fatal("the raw report is stored in plaintext")
	}
	// Still queued for a reader.
	if _, st := r.get("/api/v1/ci/runs/"+runID+"/results/"+uid, token); st["status"] != "queued" {
		t.Fatalf("before the worker: %v", st)
	}
	r.drain()
	_, st := r.get("/api/v1/ci/runs/"+runID+"/results/"+uid+"?wait=2", token)
	if st["status"] != "applied" || st["findings_created"] != float64(1) {
		t.Fatalf("after the worker: %v", st)
	}
	if n := r.count(`SELECT count(*) FROM ingest_payloads WHERE job_id = $1`, uid); n != 0 {
		t.Fatalf("%d stored parts left after the upload was applied", n)
	}
	// The envelope is not kept on the applied job either.
	var payload []byte
	_ = r.db.QueryRowContext(context.Background(), `SELECT payload FROM ingest_jobs WHERE id = $1`, uid).Scan(&payload)
	if string(payload) != "{}" {
		t.Fatalf("applied job payload = %q", payload)
	}
}

// The same body uploaded to the run twice is one upload (a retry after a
// lost answer): one job, one report slot.
func TestCIUploadAsync_SameBodyIsOneUpload(t *testing.T) {
	r := newCIRig(t)
	token, runID, repoName := r.asyncRun(t, strings.Repeat("5", 40))
	body := ciReport(repoName, ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10))
	resp1, out1 := r.post("/api/v1/ci/runs/"+runID+"/results", token, body)
	resp2, out2 := r.post("/api/v1/ci/runs/"+runID+"/results", token, body)
	if resp1.StatusCode != http.StatusAccepted || resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("accept: %d %d", resp1.StatusCode, resp2.StatusCode)
	}
	if out1["upload_id"] != out2["upload_id"] || resp2.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("second upload %v (replayed %q), want the first %v", out2, resp2.Header.Get("Idempotent-Replayed"), out1)
	}
	if n := r.count(`SELECT reports_count FROM ci_runs WHERE id = $1`, runID); n != 1 {
		t.Fatalf("reports_count = %d, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM ingest_jobs WHERE tenant_id = $1 AND kind = 'ci_results'`, r.tenant.String()); n != 1 {
		t.Fatalf("%d jobs, want 1", n)
	}
	if n := r.count(`SELECT count(*) FROM ingest_payloads WHERE tenant_id = $1`, r.tenant.String()); n != 1 {
		t.Fatalf("%d stored parts, want 1 (the replay's staged part is dropped)", n)
	}
}

// Idempotency-Key in the durable store: the same key and body replays the
// first answer; the same key with another body is 422.
func TestCIUploadAsync_IdempotencyKey(t *testing.T) {
	r := newCIRig(t)
	r.runner.SetIdempotencyStore(postgres.NewIdempotencyKeyRepository(r.db))
	token, runID, repoName := r.asyncRun(t, strings.Repeat("6", 40))
	post := func(key string, body any) (*http.Response, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.srv.URL+"/api/v1/ci/runs/"+runID+"/results", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}
	a := ciReport(repoName, ciFinding("A", "a", "low", ctis.FindingTypeVulnerability, "a.go", 1))
	b := ciReport(repoName, ciFinding("B", "b", "low", ctis.FindingTypeVulnerability, "b.go", 1))
	resp1, out1 := post("k-1", a)
	resp2, out2 := post("k-1", a)
	if resp1.StatusCode != http.StatusAccepted || resp2.StatusCode != http.StatusAccepted || out1["upload_id"] != out2["upload_id"] ||
		resp2.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %v / %d %v", resp1.StatusCode, out1, resp2.StatusCode, out2)
	}
	if resp3, out3 := post("k-1", b); resp3.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("same key, other body: %d %v", resp3.StatusCode, out3)
	}
}

// The verdict waits for the run's uploads: while one is not applied it
// answers 503 INGEST_PENDING (never a verdict over part of the results);
// once applied it judges.
func TestCIUploadAsync_GateWaitsForUploads(t *testing.T) {
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example", GateUploadWait: 300 * time.Millisecond})
	token, runID, repoName := r.asyncRun(t, strings.Repeat("7", 40))
	high := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 42)
	if resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, high)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("accept: %d %v", resp.StatusCode, out)
	}
	resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || v["code"] != "INGEST_PENDING" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("evaluate with a pending upload: %d %v", resp.StatusCode, v)
	}
	if n := r.count(`SELECT count(*) FROM ci_runs WHERE id = $1 AND status = 'evaluated'`, runID); n != 0 {
		t.Fatal("a verdict was stored over a pending upload")
	}
	r.drain()
	resp, v = r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil)
	// The applied finding is judged (the first default-branch run records
	// it as the baseline).
	sum, _ := v["summary"].(map[string]any)
	if resp.StatusCode != http.StatusOK || v["verdict"] == nil || sum["evaluated"] != float64(1) {
		t.Fatalf("evaluate after the worker: %d %v", resp.StatusCode, v)
	}
}

// The verdict request waits for an upload applied during its wait and then
// judges, instead of answering 503.
func TestCIUploadAsync_GateWaitSeesAnUploadAppliedMeanwhile(t *testing.T) {
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example", GateUploadWait: 8 * time.Second})
	token, runID, repoName := r.asyncRun(t, strings.Repeat("e", 40))
	if resp, _ := r.post("/api/v1/ci/runs/"+runID+"/results", token,
		ciReport(repoName, ciFinding("A", "a", "low", ctis.FindingTypeVulnerability, "a.go", 1))); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("accept: %d", resp.StatusCode)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = r.worker.Reconcile(context.Background())
	}()
	resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil)
	if resp.StatusCode != http.StatusOK || v["verdict"] == nil {
		t.Fatalf("evaluate while the upload is applied: %d %v", resp.StatusCode, v)
	}
}

// An upload the worker cannot apply fails the run: uploading something
// unreadable never passes the gate on silence.
func TestCIUploadAsync_UnappliedUploadFailsTheGate(t *testing.T) {
	r := newCIRig(t)
	token, runID, repoName := r.asyncRun(t, strings.Repeat("8", 40))
	low := ciFinding("Low", "go.low", "low", ctis.FindingTypeVulnerability, "a.go", 1)
	if resp, out := r.upload(runID, token, ciReport(repoName, low)); resp.StatusCode != http.StatusAccepted || out["status"] != "applied" {
		t.Fatalf("good upload: %d %v", resp.StatusCode, out)
	}
	code, out := r.postRaw("/api/v1/ci/runs/"+runID+"/results", token,
		[]byte(`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&x;</NessusClientData_v2>`))
	if code != http.StatusAccepted || out["status"] != "failed" {
		t.Fatalf("hostile upload: %d %v", code, out)
	}
	resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, nil)
	if resp.StatusCode != http.StatusOK || v["verdict"] != "fail" || !hasReason(v, cirun.ReasonUploadNotApplied) {
		t.Fatalf("verdict with an unapplied upload: %d %v", resp.StatusCode, v)
	}
}

// A verdict cannot be saved while an upload of the run is pending, even one
// accepted after the gate's wait (the save itself checks).
func TestCIUploadAsync_SaveVerdictRefusesWithPendingUpload(t *testing.T) {
	r := newCIRig(t)
	token, runID, repoName := r.asyncRun(t, strings.Repeat("9", 40))
	if resp, _ := r.post("/api/v1/ci/runs/"+runID+"/results", token,
		ciReport(repoName, ciFinding("A", "a", "low", ctis.FindingTypeVulnerability, "a.go", 1))); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("accept: %d", resp.StatusCode)
	}
	id, _ := shared.IDFromString(runID)
	err := r.repo.SaveVerdict(context.Background(), r.tenant, id, "pass", []byte(`{"reasons":[]}`), time.Now(), 0, nil)
	if err == nil || !strings.Contains(err.Error(), "still being applied") {
		t.Fatalf("SaveVerdict with a pending upload: %v", err)
	}
}

// Another tenant's run token never reads this run's upload; the upload id
// of another run under this run's token is 404.
func TestCIUploadAsync_StatusIsRunScoped(t *testing.T) {
	r := newCIRig(t)
	token, runID, repoName := r.asyncRun(t, strings.Repeat("a", 40))
	_, out := r.post("/api/v1/ci/runs/"+runID+"/results", token,
		ciReport(repoName, ciFinding("A", "a", "low", ctis.FindingTypeVulnerability, "a.go", 1)))
	uid := out["upload_id"].(string)
	// A second run of the same tenant (another commit).
	token2, runID2, _ := r.asyncRun(t, strings.Repeat("b", 40))
	if resp, _ := r.get("/api/v1/ci/runs/"+runID2+"/results/"+uid, token2); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another run's upload: %d", resp.StatusCode)
	}
	if resp, _ := r.get("/api/v1/ci/runs/"+runID+"/results/"+shared.NewID().String(), token); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown upload: %d", resp.StatusCode)
	}
}

// ctisImporterFixtures is the testdata of the pinned ctis importer.
func ctisImporterFixtures(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openctemio/ctis").Output()
	if err != nil {
		t.Skipf("ctis module dir: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "testdata", "importers")
}

// SARIF from CodeQL, semgrep and trivy, semgrep and trivy JSON and a
// gitleaks report: every finding lands on the run's repository with the
// run's branch, none is dropped. codeql-provenance names another repository
// in versionControlProvenance; the run's wins.
func TestCIUploadAsync_CodeScannerFormatsLandOnTheRunRepository(t *testing.T) {
	root := ctisImporterFixtures(t)
	for _, fx := range []string{
		"sarif/codeql.sarif", "sarif/codeql-provenance.sarif.json", "sarif/semgrep.sarif", "sarif/trivy.sarif",
		"semgrep/semgrep.json", "trivy/fs.json", "gitleaks/leaks.json",
	} {
		t.Run(fx, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, fx))
			if err != nil {
				t.Fatal(err)
			}
			r := newCIRig(t)
			token, runID, repoName := r.asyncRun(t, strings.Repeat("c", 40))
			code, out := r.postRaw("/api/v1/ci/runs/"+runID+"/results", token, body)
			if code != http.StatusAccepted || out["status"] != "applied" {
				t.Fatalf("upload: %d %v", code, out)
			}
			if out["findings_dropped_out_of_scope"] != nil && out["findings_dropped_out_of_scope"] != float64(0) {
				t.Fatalf("dropped: %v", out)
			}
			n := r.count(`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id
				WHERE f.tenant_id = $1 AND a.name = $2 AND COALESCE(f.last_seen_branch, '') = 'main'`, r.tenant.String(), repoName)
			others := r.count(`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id
				WHERE f.tenant_id = $1 AND a.name <> $2`, r.tenant.String(), repoName)
			if n == 0 || others != 0 {
				t.Fatalf("findings on the run's repository %d, elsewhere %d", n, others)
			}
		})
	}
}

// Hostile exports are stored, then refused by the worker for good with a
// fixed code; nothing is written and nothing of them is echoed.
func TestCIUploadAsync_HostileExportsRefused(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("../../etc/x.json")
	_, _ = f.Write([]byte(`{"findings": [{"title": "SQLi", "severity": "High", "description": "d", "file_path": "a.py"}]}`))
	_ = zw.Close()
	cases := map[string][]byte{
		"deep":          []byte(`{"findings": ` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}`),
		"zip traversal": zbuf.Bytes(),
		"deep sarif":    []byte(`{"version": "2.1.0", "runs": ` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}`),
		"old sarif":     []byte(`{"version": "2.0.0", "$schema": "https://json.schemastore.org/sarif-2.0.0.json", "runs": []}`),
	}
	r := newCIRig(t)
	token, runID, _ := r.asyncRun(t, strings.Repeat("d", 40))
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := r.postRaw("/api/v1/ci/runs/"+runID+"/results", token, body)
			if code == http.StatusAccepted && out["status"] != "failed" {
				t.Fatalf("accepted and applied: %v", out)
			}
			if code != http.StatusAccepted && code != http.StatusBadRequest && code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status %d: %v", code, out)
			}
		})
	}
	if n := r.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, r.tenant.String()); n != 0 {
		t.Fatalf("hostile exports wrote %d findings", n)
	}
}
