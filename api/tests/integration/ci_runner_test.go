package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// ciIdP is a CI provider (GitLab-shaped, self-managed issuer) over TLS.
type ciIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newCIIdP(t *testing.T) *ciIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &ciIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/oauth/discovery/keys"})
	})
	mux.HandleFunc("/oauth/discovery/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// token mints a GitLab CI ID token for project grp/<project> on ref.
func (p *ciIdP) token(t *testing.T, aud, project, ref, sha string, over map[string]any) string {
	t.Helper()
	now := time.Now()
	c := jwtv5.MapClaims{
		"iss": p.srv.URL, "sub": "project_path:" + project + ":ref_type:branch:ref:" + ref, "aud": aud,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": shared.NewID().String(),
		"project_path": project, "project_id": "7", "namespace_path": strings.Split(project, "/")[0],
		"ref": ref, "ref_type": "branch", "ref_protected": "false", "sha": sha, "user_login": "dev",
		"pipeline_id": "1001", "pipeline_source": "push",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type ciRig struct {
	t      *testing.T
	db     *postgres.DB
	svc    *cirunapp.Service
	repo   *postgres.CIRunRepository
	srv    *httptest.Server
	idp    *ciIdP
	tenant shared.ID
	other  shared.ID
}

func newCIRig(t *testing.T) *ciRig {
	t.Helper()
	sqldb := setupTestDB(t)
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	ing := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	idp := newCIIdP(t)
	repo := postgres.NewCIRunRepository(db)
	svc := cirunapp.NewService(cirunapp.Deps{
		Repo: repo, Verifier: oidc.NewClient(idp.srv.Client(), nil), Assets: postgres.NewAssetRepository(db),
		Branches: postgres.NewBranchRepository(db), Baseline: postgres.NewFindingRepository(db), Ingester: ing,
		Units: repo, Audit: auditapp.NewAuditService(postgres.NewAuditRepository(db), log),
	}, cirunapp.Config{WebBaseURL: "https://console.example"}, log)

	h := handler.NewCIRunnerHandler(svc, log)
	router := infrahttp.NewChiRouter()
	router.POST("/api/v1/ci/oidc/exchange", h.Exchange)
	router.POST("/api/v1/ci/runs/{id}/results", h.UploadResults, h.AuthenticateRun)
	router.POST("/api/v1/ci/runs/{id}/baseline-diff", h.BaselineDiff, h.AuthenticateRun)
	router.POST("/api/v1/ci/runs/{id}/evaluate", h.Evaluate, h.AuthenticateRun)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	r := &ciRig{t: t, db: db, svc: svc, repo: repo, srv: srv, idp: idp}
	r.tenant, r.other = r.newTenant(), r.newTenant()
	return r
}

func (r *ciRig) newTenant() shared.ID {
	r.t.Helper()
	id := shared.NewID()
	ctx := context.Background()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "ci-"+id.String()); err != nil {
		r.t.Fatalf("seed tenant: %v", err)
	}
	r.t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func (r *ciRig) trust(tenant shared.ID, rules cirun.Rules) *cirun.TrustConfig {
	r.t.Helper()
	c, err := r.svc.CreateTrustConfig(context.Background(), tenant, cirunapp.TrustConfigInput{
		Name: "gitlab-" + shared.NewID().String()[:8], Provider: "gitlab", Issuer: r.idp.srv.URL, Rules: rules,
	}, cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil {
		r.t.Fatalf("create trust config: %v", err)
	}
	return c
}

func (r *ciRig) post(path, bearer string, body any) (*http.Response, map[string]any) {
	r.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (r *ciRig) exchange(tenant shared.ID, tok string) (int, map[string]any) {
	r.t.Helper()
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": tenant.String(), "id_token": tok})
	return resp.StatusCode, out
}

func (r *ciRig) auditCount(tenant shared.ID, action, needle string) int {
	r.t.Helper()
	var n int
	if err := r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs
		WHERE tenant_id = $1 AND action = $2 AND metadata::text LIKE '%' || $3 || '%'`,
		tenant.String(), action, needle).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func ciFinding(title, rule, sev string, typ ctis.FindingType, path string, line int) ctis.Finding {
	return ctis.Finding{Type: typ, Title: title, RuleID: rule, Severity: ctis.Severity(sev),
		Location: &ctis.FindingLocation{Path: path, StartLine: line}}
}

func ciReport(repo string, findings ...ctis.Finding) map[string]any {
	return map[string]any{"report": ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: "semgrep"},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: repo}},
		Findings: findings,
	}}
}

// TestCIRunner_ExchangeUploadEvaluate is the R1+R2 acceptance, end to end
// through the real token verification, ingest and gate (RFC-051).
func TestCIRunner_ExchangeUploadEvaluate(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main", "feature/*"}})
	aud := cfg.Audience
	const sha1 = "1111111111111111111111111111111111111111"
	const sha2 = "2222222222222222222222222222222222222222"
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	// --- R1: identity ---------------------------------------------------
	mainTok := r.idp.token(t, aud, "acme/api", "main", sha1, nil)
	code, ex := r.exchange(r.tenant, mainTok)
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	token, _ := ex["token"].(string)
	runID, _ := ex["run_id"].(string)
	if !strings.HasPrefix(token, cirun.TokenPrefix) || ex["repository"] != repoName || ex["is_default_branch"] != true {
		t.Fatalf("exchange response: %v", ex)
	}
	exp, _ := time.Parse(time.RFC3339Nano, ex["expires_at"].(string))
	if d := time.Until(exp); d <= 0 || d > 15*time.Minute {
		t.Fatalf("token lifetime %s, want at most 15 minutes", d)
	}
	// A run is not a sensor.
	var sensors int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM sensors WHERE tenant_id = $1`, r.tenant.String()).Scan(&sensors)
	if sensors != 0 {
		t.Fatalf("a CI run created %d sensor rows", sensors)
	}
	if r.auditCount(r.tenant, "ci_run.token_issued", "acme/api") != 1 {
		t.Fatal("exchange not audited")
	}

	// The same OIDC token twice: replay.
	if code, _ := r.exchange(r.tenant, mainTok); code != http.StatusUnauthorized {
		t.Fatalf("replayed token: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "replay") != 1 {
		t.Fatal("replay not audited")
	}
	// Another repository, an unlisted branch, a fork-capable event: refused and audited.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "evil/api", "main", sha1, nil)); code != http.StatusUnauthorized {
		t.Fatalf("other owner: %d", code)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", "dev", sha1, nil)); code != http.StatusUnauthorized {
		t.Fatalf("unlisted ref: %d", code)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", "main", sha1,
		map[string]any{"pipeline_source": "external_pull_request_event"})); code != http.StatusUnauthorized {
		t.Fatalf("fork pull request: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "owner_not_allowed") != 1 ||
		r.auditCount(r.tenant, "ci_run.token_refused", "ref_not_allowed") != 1 ||
		r.auditCount(r.tenant, "ci_run.token_refused", "fork_pull_request") != 1 {
		t.Fatal("refusals not audited with their reason")
	}
	// Wrong audience, expired, forged: refused; not verified, so nothing is
	// written to the tenant's audit log.
	before := r.auditCount(r.tenant, "ci_run.token_refused", "")
	if code, _ := r.exchange(r.tenant, r.idp.token(t, "openctem:tenant:"+r.other.String(), "acme/api", "main", sha1, nil)); code != http.StatusUnauthorized {
		t.Fatalf("wrong audience: %d", code)
	}
	if code, _ := r.exchange(r.tenant, r.idp.token(t, aud, "acme/api", "main", sha1,
		map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix()})); code != http.StatusUnauthorized {
		t.Fatalf("expired: %d", code)
	}
	forged := r.idp.token(t, aud, "acme/api", "main", sha1, nil)
	forged = forged[:strings.LastIndex(forged, ".")+1] + "AAAA"
	if code, _ := r.exchange(r.tenant, forged); code != http.StatusUnauthorized {
		t.Fatalf("forged: %d", code)
	}
	if after := r.auditCount(r.tenant, "ci_run.token_refused", ""); after != before {
		t.Fatalf("unverified tokens wrote %d audit rows", after-before)
	}
	// Cross-tenant: the other tenant has no trust in this issuer.
	if code, _ := r.exchange(r.other, r.idp.token(t, aud, "acme/api", "main", sha1, nil)); code != http.StatusUnauthorized {
		t.Fatalf("other tenant: %d", code)
	}

	// --- R2: results and the gate ----------------------------------------
	// Default branch: one medium finding, one secret. The secret fails the
	// default-branch run (secrets always block).
	medium := ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)
	secret := ciFinding("AWS key", "aws-access-key", "high", ctis.FindingTypeSecret, "config.go", 3)
	resp, out := r.post("/api/v1/ci/runs/"+runID+"/results", token, ciReport(repoName, medium, secret))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", resp.StatusCode, out)
	}
	resp, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, map[string]int{"scan_failures": 0})
	if resp.StatusCode != http.StatusOK || v["verdict"] != "fail" || !hasReason(v, cirun.ReasonSecret) || hasReason(v, cirun.ReasonSeverity) {
		t.Fatalf("default branch verdict: %d %v", resp.StatusCode, v)
	}
	// The report's branch is the token's, not the report's.
	var branch string
	_ = r.db.QueryRowContext(ctx, `SELECT COALESCE(last_seen_branch, '') FROM findings WHERE tenant_id = $1 AND title = 'Weak hash'`,
		r.tenant.String()).Scan(&branch)
	if branch != "main" {
		t.Fatalf("finding branch = %q", branch)
	}

	// A report naming another repository is refused.
	prTok := r.idp.token(t, aud, "acme/api", "feature/login", sha2, nil)
	code, ex2 := r.exchange(r.tenant, prTok)
	if code != http.StatusCreated || ex2["is_default_branch"] != false || ex2["default_branch"] != "main" {
		t.Fatalf("feature exchange: %d %v", code, ex2)
	}
	prToken, prRun := ex2["token"].(string), ex2["run_id"].(string)
	if resp, out := r.post("/api/v1/ci/runs/"+prRun+"/results", prToken, ciReport("github.com/someone/else", medium)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign repository report: %d %v", resp.StatusCode, out)
	}
	// One run's token cannot act on another run.
	if resp, _ := r.post("/api/v1/ci/runs/"+runID+"/evaluate", prToken, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("token for another run: %d", resp.StatusCode)
	}

	// The feature branch reports the old medium and a new high: the new
	// high fails (new findings only); the old medium is pre-existing.
	high := ciFinding("SQL injection", "go.sqli", "high", ctis.FindingTypeVulnerability, "db.go", 42)
	if resp, out := r.post("/api/v1/ci/runs/"+prRun+"/results", prToken, ciReport(repoName, medium, high)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("feature upload: %d %v", resp.StatusCode, out)
	}
	resp, v = r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, nil)
	if v["verdict"] != "fail" || !hasReason(v, cirun.ReasonSeverity) {
		t.Fatalf("feature verdict: %v", v)
	}
	sum, _ := v["summary"].(map[string]any)
	if sum["new"].(float64) != 1 || sum["pre_existing"].(float64) != 1 || sum["blocking"].(float64) != 1 {
		t.Fatalf("summary = %v", sum)
	}
	links, _ := v["links"].(map[string]any)
	if !strings.HasPrefix(links["run"].(string), "https://console.example/ci-runners/") {
		t.Fatalf("links = %v", links)
	}

	// Accepted risk is honored.
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'accepted' WHERE tenant_id = $1 AND title = 'SQL injection'`,
		r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, v = r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, nil); v["verdict"] != "pass" {
		t.Fatalf("accepted risk: %v", v)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'confirmed' WHERE tenant_id = $1 AND title = 'SQL injection'`,
		r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	// A scan failure fails.
	if _, v = r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, map[string]int{"scan_failures": 1}); !hasReason(v, cirun.ReasonScanFailure) {
		t.Fatalf("scan failure: %v", v)
	}
	// A repository policy in warn mode passes and says it would fail.
	run, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(prRun))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := r.svc.CreateGatePolicy(ctx, r.tenant, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository,
		ScopeID: &run.RepositoryAssetID, Mode: cirun.ModeWarn}, cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, v = r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, nil); v["verdict"] != "pass" || v["would_fail"] != true {
		t.Fatalf("warn policy: %v", v)
	}
	if err := r.svc.DeleteGatePolicy(ctx, r.tenant, pol.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	// A policy for another tenant's repository is refused as not found.
	if _, err := r.svc.CreateGatePolicy(ctx, r.other, cirunapp.GatePolicyInput{ScopeType: cirun.ScopeRepository,
		ScopeID: &run.RepositoryAssetID}, cirunapp.Actor{}); err == nil {
		t.Fatal("policy on another tenant's repository accepted")
	}

	// Break-glass for the commit passes the failing run, audited each use.
	if _, err := r.svc.CreateOverride(ctx, r.tenant, cirunapp.OverrideInput{RepositoryAssetID: run.RepositoryAssetID,
		CommitSHA: sha2[:12], Reason: "hotfix for the login outage"}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if _, v = r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, nil); v["verdict"] != "pass" || v["override"] == nil {
		t.Fatalf("override: %v", v)
	}
	if r.auditCount(r.tenant, "ci_gate_override.used", prRun) != 1 || r.auditCount(r.tenant, "ci_gate_override.created", "hotfix") != 1 {
		t.Fatal("break-glass not audited")
	}
	// Another tenant cannot break-glass this repository.
	if _, err := r.svc.CreateOverride(ctx, r.other, cirunapp.OverrideInput{RepositoryAssetID: run.RepositoryAssetID,
		CommitSHA: sha2, Reason: "cross-tenant attempt here"}, cirunapp.Actor{}); err == nil {
		t.Fatal("override on another tenant's repository accepted")
	}

	// Cross-tenant reads of the run are not found.
	if _, err := r.svc.GetRun(ctx, r.other, run.ID); err == nil {
		t.Fatal("another tenant read the run")
	}
	if runs, total, err := r.svc.ListRuns(ctx, r.other, cirun.RunFilter{}); err != nil || total != 0 || len(runs) != 0 {
		t.Fatalf("other tenant lists %d runs (%v)", total, err)
	}

	// An expired run token is refused.
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET token_expires_at = now() - interval '1 second' WHERE id = $1`, prRun); err != nil {
		t.Fatal(err)
	}
	if resp, _ := r.post("/api/v1/ci/runs/"+prRun+"/evaluate", prToken, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired run token: %d", resp.StatusCode)
	}
	// Garbage tokens are refused.
	if resp, _ := r.post("/api/v1/ci/runs/"+prRun+"/evaluate", "octci_"+strings.Repeat("A", 43), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown run token: %d", resp.StatusCode)
	}

	// No token, ours or the CI provider's, is ever written to the audit log.
	var leaked int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1
		AND (metadata::text LIKE '%octci_%' OR metadata::text LIKE '%' || $2 || '%' OR message LIKE '%octci_%')`,
		r.tenant.String(), mainTok[:40]).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("%d audit rows carry a token", leaked)
	}
}

func hasReason(v map[string]any, code string) bool {
	rs, _ := v["reasons"].([]any)
	for _, r := range rs {
		if m, ok := r.(map[string]any); ok && m["code"] == code {
			return true
		}
	}
	return false
}
