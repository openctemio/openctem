package integration

// CI OIDC providers beyond GitHub Actions and GitLab CI, end to end through
// the real verification (discovery, JWKS, signature), the trust rules, the
// exchange endpoint and the gate. Tokens are signed by a local identity
// provider that answers on the providers' real issuer addresses (the HTTP
// client dials it for every host) and mirror each provider's documented
// claim shape (research note 66).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// providerIdP serves discovery and keys for any issuer path on any host.
type providerIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newProviderIdP(t *testing.T) *providerIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &providerIdP{key: key}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if prefix, ok := strings.CutSuffix(r.URL.Path, "/.well-known/openid-configuration"); ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://" + r.Host + prefix, "jwks_uri": "https://" + r.Host + "/keys"})
			return
		}
		if r.URL.Path == "/keys" {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// client dials the local provider whatever the host (test only: the
// certificate cannot name the real hosts).
func (p *providerIdP) client() *http.Client {
	addr := p.srv.Listener.Addr().String()
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local test identity provider
	}}
}

func (p *providerIdP) sign(t *testing.T, claims map[string]any, over map[string]any) string {
	t.Helper()
	now := time.Now()
	c := jwtv5.MapClaims{"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		c[k] = v
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

const (
	pAzOrg   = "0ca3ddd9-1111-4222-8333-444455556666"
	pAzProj  = "7a1b2c3d-1111-4222-8333-444455556666"
	pCCOrg   = "11111111-2222-4333-8444-555566667777"
	pCCProj  = "22222222-3333-4444-8555-666677778888"
	pBBWS    = "44444444-5555-4666-8777-888899990000"
	pBBRepo  = "55555555-6666-4777-8888-999900001111"
	pBBRepo2 = "56565656-6666-4777-8888-999900001111"
	pSHA     = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
)

type providerRig struct {
	*ciRig
	idp *providerIdP
}

func newProviderRig(t *testing.T) *providerRig {
	t.Helper()
	idp := newProviderIdP(t)
	r := newCIRigWith(t, cirunapp.Config{WebBaseURL: "https://console.example"}, func(d *cirunapp.Deps) {
		d.Verifier = oidc.NewClient(idp.client(), nil)
	})
	return &providerRig{ciRig: r, idp: idp}
}

func (r *providerRig) trustFor(tenant shared.ID, provider cirun.Provider, issuer string, rules cirun.Rules) *cirun.TrustConfig {
	r.t.Helper()
	c, err := r.svc.CreateTrustConfig(context.Background(), tenant, cirunapp.TrustConfigInput{
		Name: string(provider) + "-" + shared.NewID().String()[:8], Provider: string(provider), Issuer: issuer, Rules: rules,
	}, cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil {
		r.t.Fatalf("create %s trust: %v", provider, err)
	}
	return c
}

func (r *providerRig) exchangeWith(tenant shared.ID, tok string, hints map[string]string) (int, map[string]any) {
	r.t.Helper()
	body := map[string]string{"tenant_id": tenant.String(), "id_token": tok}
	for k, v := range hints {
		body[k] = v
	}
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", body)
	return resp.StatusCode, out
}

func (r *providerRig) commitVerified(runID string) bool {
	r.t.Helper()
	var v bool
	if err := r.db.QueryRowContext(context.Background(), `SELECT commit_verified FROM ci_runs WHERE id = $1`, runID).Scan(&v); err != nil {
		r.t.Fatal(err)
	}
	return v
}

func TestCIProviders_AzurePipelines(t *testing.T) {
	r := newProviderRig(t)
	cfg := r.trustFor(r.tenant, cirun.ProviderAzureDevOps, cirun.AzureDevOpsIssuer(pAzOrg), cirun.Rules{Owners: []string{"acme"}})
	if cfg.Audience != cirun.AzureDevOpsAudience {
		t.Fatalf("audience = %q", cfg.Audience)
	}
	claims := map[string]any{
		"iss": cfg.Issuer, "sub": "p://acme/Payments/payments-ci", "aud": cirun.AzureDevOpsAudience,
		"org_id": pAzOrg, "prj_id": pAzProj, "def_id": "12", "run_id": "345", "rpo_id": "acme/api",
		"rpo_uri": "https://github.com/acme/api.git", "rpo_ver": pSHA, "rpo_ref": "refs/heads/main",
	}
	jti := func() map[string]any { return map[string]any{"jti": shared.NewID().String()} }
	tok := r.idp.sign(t, claims, jti())
	code, ex := r.exchangeWith(r.tenant, tok, map[string]string{"commit_sha": strings.Repeat("0", 40)})
	if code != http.StatusCreated || ex["repository"] != "github.com/acme/api" || ex["commit_sha"] != pSHA {
		t.Fatalf("azure exchange: %d %v (a signed commit must win over the hint)", code, ex)
	}
	if !r.commitVerified(ex["run_id"].(string)) {
		t.Fatal("azure commit not verified")
	}
	if code, _ := r.exchangeWith(r.tenant, tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("replayed azure token: %d", code)
	}
	// Another tenant that does not trust the organization.
	if code, _ := r.exchangeWith(r.other, r.idp.sign(t, claims, jti()), nil); code != http.StatusUnauthorized {
		t.Fatalf("azure token accepted by an organization that does not trust it: %d", code)
	}
	cases := map[string]map[string]any{
		"another organization's token":  {"org_id": "99999999-1111-4222-8333-444455556666"},
		"a service connection token":    {"sub": "sc://acme/Payments/conn", "rpo_uri": nil, "rpo_ver": nil, "rpo_ref": nil, "prj_id": nil},
		"a pull request (maybe a fork)": {"rpo_ref": "refs/pull/9/merge"},
		"an expired token":              {"iat": time.Now().Add(-20 * time.Minute).Unix(), "nbf": time.Now().Add(-20 * time.Minute).Unix(), "exp": time.Now().Add(-10 * time.Minute).Unix()},
		"another audience":              {"aud": "openctem:tenant:" + r.tenant.String()},
		"another issuer":                {"iss": cirun.AzureDevOpsIssuer("99999999-1111-4222-8333-444455556666")},
		"no jti":                        {"jti": nil},
	}
	for name, over := range cases {
		o := jti()
		for k, v := range over {
			o[k] = v
		}
		if code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims, o), nil); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %v", name, code, ex)
		}
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", cirun.RefuseOrganization) != 1 ||
		r.auditCount(r.tenant, "ci_run.token_refused", cirun.RefuseForkPullRequest) != 1 {
		t.Fatal("azure refusals not audited")
	}
}

func TestCIProviders_BitbucketPipelines(t *testing.T) {
	r := newProviderRig(t)
	cfg := r.trustFor(r.tenant, cirun.ProviderBitbucket, cirun.BitbucketIssuer("acme"),
		cirun.Rules{Owners: []string{"acme"}, WorkspaceUUID: "{" + pBBWS + "}"})
	claims := func(repo string) map[string]any {
		return map[string]any{
			"iss": cfg.Issuer, "sub": "{" + repo + "}:{step}", "aud": cfg.Audience, "workspaceUuid": "{" + pBBWS + "}",
			"repositoryUuid": "{" + repo + "}", "pipelineUuid": "{" + shared.NewID().String() + "}",
			"stepUuid": "{" + shared.NewID().String() + "}", "branchName": "main", "commitSha": pSHA,
		}
	}
	tok := r.idp.sign(t, claims(pBBRepo), nil) // no jti: the token's hash is its replay key
	code, ex := r.exchangeWith(r.tenant, tok, map[string]string{"repository": "acme/api"})
	if code != http.StatusCreated || ex["repository"] != "bitbucket.org/acme/api" {
		t.Fatalf("bitbucket exchange: %d %v", code, ex)
	}
	if code, _ := r.exchangeWith(r.tenant, tok, map[string]string{"repository": "acme/api"}); code != http.StatusUnauthorized {
		t.Fatalf("replayed bitbucket token: %d", code)
	}
	// Another repository of the workspace cannot report under that name.
	if code, _ := r.exchangeWith(r.tenant, r.idp.sign(t, claims(pBBRepo2), nil), map[string]string{"repository": "api"}); code != http.StatusUnauthorized {
		t.Fatalf("name of another repository taken: %d", code)
	}
	if r.auditCount(r.tenant, "ci_run.token_refused", cirunapp.RefuseRepositoryBinding) != 1 {
		t.Fatal("repository binding refusal not audited")
	}
	// Under its own name it reports.
	if code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims(pBBRepo2), nil), map[string]string{"repository": "web"}); code != http.StatusCreated {
		t.Fatalf("second repository: %d %v", code, ex)
	}
	// No repository name, another workspace, another tenant's audience.
	if code, _ := r.exchangeWith(r.tenant, r.idp.sign(t, claims(pBBRepo), nil), nil); code != http.StatusUnauthorized {
		t.Fatalf("no repository name: %d", code)
	}
	if code, _ := r.exchangeWith(r.tenant, r.idp.sign(t, claims(pBBRepo), map[string]any{"workspaceUuid": "{" + shared.NewID().String() + "}"}),
		map[string]string{"repository": "api"}); code != http.StatusUnauthorized {
		t.Fatalf("another workspace: %d", code)
	}
	otherCfg := r.trustFor(r.other, cirun.ProviderBitbucket, cirun.BitbucketIssuer("acme"),
		cirun.Rules{Owners: []string{"acme"}, WorkspaceUUID: pBBWS})
	// A token minted for the second organization is refused by the first,
	// and the other way round: the audience names the organization.
	if code, _ := r.exchangeWith(r.tenant, r.idp.sign(t, claims(pBBRepo), map[string]any{"aud": otherCfg.Audience}),
		map[string]string{"repository": "api"}); code != http.StatusUnauthorized {
		t.Fatalf("another organization's audience: %d", code)
	}
	if code, _ := r.exchangeWith(r.other, r.idp.sign(t, claims(pBBRepo), nil), map[string]string{"repository": "api"}); code != http.StatusUnauthorized {
		t.Fatalf("token for the first organization accepted by the second: %d", code)
	}
}

func TestCIProviders_CircleCI(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	cfg := r.trustFor(r.tenant, cirun.ProviderCircleCI, cirun.CircleCIIssuer(pCCOrg), cirun.Rules{Repositories: []string{"acme/api"}})
	const ns = "oidc.circleci.com/"
	claims := func() map[string]any {
		return map[string]any{
			"iss": cfg.Issuer, "sub": "org/" + pCCOrg + "/project/" + pCCProj + "/user/u", "aud": cfg.Audience,
			ns + "org-id": pCCOrg, ns + "project-id": pCCProj, ns + "workflow-id": shared.NewID().String(),
			ns + "job-id": shared.NewID().String(), ns + "vcs-origin": "github.com/acme/api", ns + "vcs-ref": "refs/heads/main",
			ns + "ssh-rerun": false,
		}
	}
	// CircleCI signs no commit: without the job's report the run is refused.
	if code, _ := r.exchangeWith(r.tenant, r.idp.sign(t, claims(), nil), nil); code != http.StatusUnauthorized {
		t.Fatalf("no commit: %d", code)
	}
	code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims(), nil), map[string]string{"commit_sha": pSHA})
	if code != http.StatusCreated || ex["repository"] != "github.com/acme/api" || ex["commit_sha"] != pSHA {
		t.Fatalf("circleci exchange: %d %v", code, ex)
	}
	runID, token := ex["run_id"].(string), ex["token"].(string)
	if r.commitVerified(runID) {
		t.Fatal("a reported commit is marked verified")
	}
	// A break-glass for that commit does not apply to a commit the token
	// does not prove.
	run, err := r.svc.GetRun(ctx, r.tenant, shared.MustIDFromString(runID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.CreateOverride(ctx, r.tenant, cirunapp.OverrideInput{RepositoryAssetID: run.RepositoryAssetID,
		CommitSHA: pSHA, Reason: "hotfix for the login outage"}, cirunapp.Actor{Email: "admin@acme.test"}); err != nil {
		t.Fatal(err)
	}
	if _, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", token, map[string]int{"scan_failures": 1}); v["verdict"] != "fail" || v["override"] != nil {
		t.Fatalf("break-glass applied to an unverified commit: %v", v)
	}
	for name, over := range map[string]map[string]any{
		"ssh re-run":                    {ns + "ssh-rerun": true},
		"another organization":          {ns + "org-id": "99999999-2222-4333-8444-555566667777"},
		"the organization's audience":   {"aud": pCCOrg},
		"a pull request (maybe a fork)": {ns + "vcs-ref": "refs/pull/3/head"},
		"another repository":            {ns + "vcs-origin": "github.com/evil/api"},
		"no expiry":                     {"exp": nil},
	} {
		if code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims(), over), map[string]string{"commit_sha": pSHA}); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %v", name, code, ex)
		}
	}
}

func TestCIProviders_Jenkins(t *testing.T) {
	r := newProviderRig(t)
	issuer := r.idp.srv.URL + "/oidc"
	cfg := r.trustFor(r.tenant, cirun.ProviderJenkins, issuer, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	claims := map[string]any{
		"iss": issuer, "sub": "https://jenkins.acme.example/job/acme/job/api/job/main/", "aud": cfg.Audience,
		"build_number": 42, "repository": "https://github.com/acme/api.git", "branch": "main", "sha": pSHA,
	}
	code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims, nil), nil)
	if code != http.StatusCreated || ex["repository"] != "github.com/acme/api" {
		t.Fatalf("jenkins exchange: %d %v", code, ex)
	}
	var wf string
	if err := r.db.QueryRowContext(context.Background(), `SELECT p.workflow_path FROM ci_runs r JOIN ci_pipelines p
		ON p.tenant_id = r.tenant_id AND p.id = r.pipeline_id WHERE r.id = $1`, ex["run_id"]).Scan(&wf); err != nil || wf != "acme/api" {
		t.Fatalf("jenkins pipeline = %q %v", wf, err)
	}
	for name, over := range map[string]map[string]any{
		"a pull request build (maybe a fork)": {"branch": "PR-7", "sub": "https://jenkins.acme.example/job/acme/job/api/job/PR-7/"},
		"no repository claim":                 {"repository": nil},
		"an unlisted branch":                  {"branch": "dev"},
		"another audience":                    {"aud": "openctem:tenant:" + r.other.String()},
		"lifetime over a day":                 {"exp": time.Now().Add(48 * time.Hour).Unix()},
	} {
		if code, ex := r.exchangeWith(r.tenant, r.idp.sign(t, claims, over), nil); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %v", name, code, ex)
		}
	}
}

// The trust preview verifies a sample against the draft configuration's
// issuer, shows the claims and the rule outcome, and records nothing: the
// same token is still exchanged afterwards.
func TestCIProviders_TrustPreview(t *testing.T) {
	r := newProviderRig(t)
	ctx := context.Background()
	issuer := cirun.CircleCIIssuer(pCCOrg)
	aud := cirun.DefaultAudience(r.tenant)
	const ns = "oidc.circleci.com/"
	tok := r.idp.sign(t, map[string]any{
		"iss": issuer, "sub": "org/x/project/y/user/z", "aud": aud, ns + "org-id": pCCOrg, ns + "project-id": pCCProj,
		ns + "workflow-id": shared.NewID().String(), ns + "vcs-origin": "github.com/acme/api", ns + "vcs-ref": "refs/heads/main",
		"email": "dev@acme.test",
	}, map[string]any{"iat": time.Now().Add(-3 * time.Hour).Unix(), "nbf": time.Now().Add(-3 * time.Hour).Unix(),
		"exp": time.Now().Add(-2 * time.Hour).Unix()})
	draft := cirunapp.TrustConfigInput{Provider: "circleci", Issuer: issuer, Rules: cirun.Rules{Repositories: []string{"acme/api"}}}
	out, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: draft, IDToken: tok, Hints: cirun.Hints{CommitSHA: pSHA}})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Verified || !out.Expired || !out.Admitted || out.Normalized == nil || out.Normalized.CommitVerified ||
		out.Repository != "github.com/acme/api" || out.Claims["email"] != nil {
		t.Fatalf("preview = %+v %+v", out, out.Normalized)
	}
	draft.Rules = cirun.Rules{Repositories: []string{"acme/web"}}
	if out, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: draft, IDToken: tok, Hints: cirun.Hints{CommitSHA: pSHA}}); err != nil ||
		out.Admitted || out.Refusal == nil || out.Refusal.Code != cirun.RefuseRepository {
		t.Fatalf("refusing preview = %+v %v", out, err)
	}
	// Signed by another key: shown, not verified.
	other := newProviderIdP(t)
	if out, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: draft, IDToken: other.sign(t, map[string]any{
		"iss": issuer, "sub": "s", "aud": aud}, nil)}); err != nil || out.Verified || out.VerifyError == "" {
		t.Fatalf("forged preview = %+v %v", out, err)
	}
	// An invalid draft fetches nothing.
	if _, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: cirunapp.TrustConfigInput{Provider: "jenkins",
		Issuer: "http://169.254.169.254/latest", Rules: cirun.Rules{Owners: []string{"acme"}}}, IDToken: tok}); err == nil {
		t.Fatal("preview of an http issuer accepted")
	}
	// Nothing recorded: a live token previewed is still exchanged once.
	_ = r.trustFor(r.tenant, cirun.ProviderCircleCI, issuer, cirun.Rules{Repositories: []string{"acme/api"}})
	live := r.idp.sign(t, map[string]any{
		"iss": issuer, "sub": "org/x/project/y/user/z", "aud": aud, ns + "org-id": pCCOrg, ns + "project-id": pCCProj,
		ns + "workflow-id": shared.NewID().String(), ns + "vcs-origin": "github.com/acme/api", ns + "vcs-ref": "refs/heads/main",
	}, nil)
	if _, err := r.svc.PreviewTrust(ctx, r.tenant, cirunapp.PreviewInput{Config: draft, IDToken: live}); err != nil {
		t.Fatal(err)
	}
	if code, ex := r.exchangeWith(r.tenant, live, map[string]string{"commit_sha": pSHA}); code != http.StatusCreated {
		t.Fatalf("exchange after preview: %d %v", code, ex)
	}
}
