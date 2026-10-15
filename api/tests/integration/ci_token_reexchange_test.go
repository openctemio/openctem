package integration

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestCIToken_ReExchange: the same OIDC token exchanged again gets a token
// for the same run only, a bounded number of times; a different token under
// a used jti, another organization or a closed run is refused, with a reason
// only once the organization's trust configuration admitted the token.
func TestCIToken_ReExchange(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	const sha = "5555555555555555555555555555555555555555"
	repoName := strings.ToLower(strings.TrimPrefix(r.idp.srv.URL, "https://")) + "/acme/api"
	exchange := func(tenant shared.ID, tok string, aggregate bool) (int, map[string]any) {
		t.Helper()
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]any{"tenant_id": tenant.String(), "id_token": tok, "aggregate": aggregate})
		return resp.StatusCode, out
	}
	upload := func(run, token string) int {
		t.Helper()
		resp, _ := r.post("/api/v1/ci/runs/"+run+"/results", token,
			ciReport(repoName, ciFinding("Weak hash", "go.weak-hash", "medium", ctis.FindingTypeVulnerability, "hash.go", 10)))
		return resp.StatusCode
	}

	// --- one job's token: same run on every exchange, up to the bound ---
	jti := shared.NewID().String()
	tok := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"jti": jti, "job_id": "801", "pipeline_id": "2001"})
	code, first := exchange(r.tenant, tok, true)
	if code != http.StatusCreated || first["aggregate"] != true {
		t.Fatalf("first exchange: %d %v", code, first)
	}
	run := first["run_id"].(string)
	tokens := []string{first["token"].(string)}
	for n := 2; n <= cirun.MaxTokenExchanges; n++ {
		code, again := exchange(r.tenant, tok, true)
		if code != http.StatusCreated || again["run_id"] != run {
			t.Fatalf("re-exchange %d: %d %v, want run %s", n, code, again, run)
		}
		tokens = append(tokens, again["token"].(string))
	}
	for i, tk := range tokens {
		if c := upload(run, tk); c != http.StatusCreated {
			t.Fatalf("upload with token %d: %d", i+1, c)
		}
	}
	code, over := exchange(r.tenant, tok, true)
	if code != http.StatusUnauthorized || over["code"] != "CI_TOKEN_REPLAY_LIMIT" || !strings.Contains(over["message"].(string), run) {
		t.Fatalf("past the bound: %d %v", code, over)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", "replay_limit") != 1 {
		t.Fatal("bound refusal not audited")
	}

	// --- another job of the same pipeline run joins the same run ---
	codeB, b := exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha,
		map[string]any{"job_id": "802", "pipeline_id": "2001"}), true)
	if codeB != http.StatusCreated || b["run_id"] != run {
		t.Fatalf("second job: %d %v, want run %s", codeB, b, run)
	}
	// The same pipeline id in another project is another pipeline: never this run.
	codeP, p := exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha,
		map[string]any{"job_id": "803", "pipeline_id": "2001", "project_id": "8"}), true)
	if codeP == http.StatusCreated && p["run_id"] == run {
		t.Fatalf("another project's job joined the run: %v", p)
	}

	// --- a forged token under the used jti: replay, no detail ---
	forged := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"jti": jti, "job_id": "999", "pipeline_id": "2001"})
	code, f := exchange(r.tenant, forged, true)
	if code != http.StatusUnauthorized || f["code"] != "CI_TOKEN_REPLAY" || strings.Contains(f["message"].(string), run) {
		t.Fatalf("forged token under a used jti: %d %v", code, f)
	}

	// --- another organization: its trust configuration does not admit the
	// token (audience names this tenant), and it learns nothing ---
	r.trust(r.other, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	tok2 := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"job_id": "804", "pipeline_id": "2001"})
	if code, _ := exchange(r.tenant, tok2, true); code != http.StatusCreated {
		t.Fatalf("job 804: %d", code)
	}
	code, o := exchange(r.other, tok2, true)
	if code != http.StatusUnauthorized || o["code"] != "CI_TOKEN_NOT_TRUSTED" || strings.Contains(o["message"].(string), run) {
		t.Fatalf("token re-exchanged into another organization: %d %v", code, o)
	}
	var otherRuns int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1`, r.other.String()).Scan(&otherRuns)
	if otherRuns != 0 {
		t.Fatalf("another organization got %d runs", otherRuns)
	}

	// --- a stranger's project on the same issuer: generic refusal, no rule detail ---
	code, s := exchange(r.tenant, r.idp.token(t, cfg.Audience, "evil/api", "main", sha, nil), true)
	if code != http.StatusUnauthorized || s["code"] != "CI_TOKEN_NOT_TRUSTED" || strings.Contains(s["message"].(string), "acme") {
		t.Fatalf("stranger: %d %v", code, s)
	}

	// --- concurrent re-exchanges of one token: one run, within the bound ---
	tok3 := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"job_id": "805", "pipeline_id": "2002"})
	var wg sync.WaitGroup
	got := make([]string, 8)
	codes := make([]int, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, out := exchange(r.tenant, tok3, true)
			codes[i] = c
			got[i], _ = out["run_id"].(string)
		}(i)
	}
	wg.Wait()
	ok, runID := 0, ""
	for i := range got {
		if codes[i] == http.StatusCreated {
			ok++
			if runID == "" {
				runID = got[i]
			} else if got[i] != runID {
				t.Fatalf("concurrent re-exchanges got different runs: %v", got)
			}
		}
	}
	if ok != cirun.MaxTokenExchanges {
		t.Fatalf("concurrent re-exchanges admitted %d, want exactly %d", ok, cirun.MaxTokenExchanges)
	}

	// --- once the run is evaluated, a re-exchange is told the run closed ---
	tok4 := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"job_id": "806", "pipeline_id": "2003"})
	code, g := exchange(r.tenant, tok4, true)
	if code != http.StatusCreated {
		t.Fatalf("gate job: %d %v", code, g)
	}
	if resp, _ := r.post("/api/v1/ci/runs/"+g["run_id"].(string)+"/evaluate", g["token"].(string), map[string]any{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate: %d", resp.StatusCode)
	}
	code, closed := exchange(r.tenant, tok4, true)
	if code != http.StatusUnauthorized || closed["code"] != "CI_TOKEN_REPLAY_RUN_CLOSED" || !strings.Contains(closed["message"].(string), g["run_id"].(string)) {
		t.Fatalf("re-exchange after the verdict: %d %v", code, closed)
	}
}

// TestCIToken_ReExchangeAfterLostCreation: the first exchange of a plain run
// claimed the token and chose the run id, then failed before writing the
// run. The same token again creates that run, under that id, once.
func TestCIToken_ReExchangeAfterLostCreation(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	const sha = "6666666666666666666666666666666666666666"
	jti := shared.NewID().String()
	tok := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"jti": jti})
	planned := shared.NewID()
	sum := sha256.Sum256([]byte(tok))
	if ok, _, err := r.repo.ClaimReplay(ctx, cirun.Replay{Issuer: r.idp.srv.URL, JTI: jti, TenantID: &r.tenant,
		TokenSHA256: sum[:], RunID: &planned, ExpiresAt: time.Now().Add(time.Hour)}); err != nil || !ok {
		t.Fatalf("seed the lost first exchange: %v %v", ok, err)
	}
	code, ex := r.exchange(r.tenant, tok)
	if code != http.StatusCreated || ex["run_id"] != planned.String() {
		t.Fatalf("re-exchange after a lost creation: %d %v, want run %s", code, ex, planned)
	}
	code, again := r.exchange(r.tenant, tok)
	if code != http.StatusCreated || again["run_id"] != planned.String() {
		t.Fatalf("third exchange: %d %v", code, again)
	}
	var runs int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND commit_sha = $2`, r.tenant.String(), sha).Scan(&runs)
	if runs != 1 {
		t.Fatalf("%d runs, want 1", runs)
	}
}
