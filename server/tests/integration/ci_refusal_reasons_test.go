package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A verified token refused by the pipeline definitions rule tells the job
// the rule and its own value (never the configuration's); the audit row
// keeps the value and the configuration; "add to Pipeline definitions" is an
// ordinary audited change of that configuration, after which the same token
// is admitted; another tenant cannot change the configuration.
func TestCIRefusal_WorkflowValueAndAllow(t *testing.T) {
	r := newCIRig(t)
	host := strings.TrimPrefix(r.idp.url, "https://")
	listed := host + "/acme/api//.gitlab-ci.yml@refs/heads/main"
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, WorkflowRefs: []string{listed}})
	value := host + "/acme/api//ci/scan.yml@refs/heads/main"
	sha := "8888888888888888888888888888888888888888"
	raw := r.idp.token(t, cfg.Audience, "acme/api", "main", sha, map[string]any{"ci_config_ref_uri": value})

	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": raw})
	msg, _ := out["message"].(string)
	if resp.StatusCode != http.StatusUnauthorized || out["code"] != "CI_TOKEN_NOT_TRUSTED" ||
		!strings.Contains(msg, "pipeline files it lists") || !strings.Contains(msg, value) {
		t.Fatalf("refusal: %d %v", resp.StatusCode, out)
	}
	if strings.Contains(msg, ".gitlab-ci.yml") || strings.Contains(msg, cfg.Name) {
		t.Fatalf("the job learned the configuration's values: %s", msg)
	}

	list, err := r.svc.RecentRefusals(context.Background(), r.tenant, 5)
	if err != nil || len(list) == 0 {
		t.Fatalf("refusals: %v %v", list, err)
	}
	got := list[0]
	if got.WorkflowDefinition != value || got.Issuer != r.idp.url || len(got.Configs) != 1 ||
		got.Configs[0].ID != cfg.ID.String() || got.Configs[0].Code != cirun.RefuseWorkflow {
		t.Fatalf("refusal record: %+v", got)
	}

	refusalID := shared.MustIDFromString(got.ID)
	admin := cirunapp.Actor{Email: "admin@acme.test"}

	// Another tenant cannot touch the configuration with this refusal.
	if _, _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.other, cfg.ID, refusalID,
		cirunapp.Actor{Email: "admin@other.test"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant allow: %v", err)
	}
	// Another tenant's refusal id is not found in this tenant.
	ocfg := r.trust(r.other, cirun.Rules{Owners: []string{"acme"}, WorkflowRefs: []string{listed}})
	oraw := r.idp.token(t, ocfg.Audience, "acme/api", "main", sha, map[string]any{"ci_config_ref_uri": host + "/acme/api//other.yml@refs/heads/main"})
	if code, _ := r.exchange(r.other, oraw); code != http.StatusUnauthorized {
		t.Fatalf("other tenant's token admitted: %d", code)
	}
	olist, err := r.svc.RecentRefusals(context.Background(), r.other, 1)
	if err != nil || len(olist) != 1 {
		t.Fatalf("other tenant's refusal: %v %v", olist, err)
	}
	if _, _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, shared.MustIDFromString(olist[0].ID),
		admin); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant's refusal id: %v", err)
	}

	next, allowed, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, refusalID, admin)
	if err != nil || !changed || len(next.Rules.WorkflowRefs) != 2 || allowed.Kind != cirunapp.AllowWorkflowRef || allowed.Value != value {
		t.Fatalf("allow: %v %v %+v %+v", err, changed, allowed, next)
	}
	if _, _, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, refusalID, admin); err != nil || changed {
		t.Fatalf("allow again: %v %v", err, changed)
	}
	var audited int
	_ = r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1
		AND action = 'ci_trust_config.updated' AND resource_id = $2`, r.tenant.String(), cfg.ID.String()).Scan(&audited)
	if audited != 1 {
		t.Fatalf("audit rows of the allow: %d, want 1", audited)
	}
	if code, ex := r.exchange(r.tenant, raw); code != http.StatusCreated {
		t.Fatalf("after allow: %d %v", code, ex)
	}
}

// A ref refusal quotes the job's ref; "allow this branch" adds it.
func TestCIRefusal_RefAllow(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	raw := r.idp.token(t, cfg.Audience, "acme/api", "release", "9999999999999999999999999999999999999999", nil)
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": raw})
	msg, _ := out["message"].(string)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(msg, "branches and tags it lists") || !strings.Contains(msg, "release") {
		t.Fatalf("refusal: %d %v", resp.StatusCode, out)
	}
	list, err := r.svc.RecentRefusals(context.Background(), r.tenant, 1)
	if err != nil || len(list) != 1 {
		t.Fatalf("refusals: %v %v", list, err)
	}
	if _, allowed, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, shared.MustIDFromString(list[0].ID),
		cirunapp.Actor{Email: "admin@acme.test"}); err != nil || !changed || allowed.Kind != cirunapp.AllowRef || allowed.Value != "refs/heads/release" {
		t.Fatalf("allow ref: %v %v %+v", err, changed, allowed)
	}
	if code, ex := r.exchange(r.tenant, raw); code != http.StatusCreated {
		t.Fatalf("after allow: %d %v", code, ex)
	}
}

// A token for an issuer no configuration has never reaches the tenant's
// audit log, but a bounded per-issuer record does (throttled, counted),
// only for a tenant that has a trust configuration; keys unavailable record
// the cause class, which the job is told too.
func TestCIRefusal_UnverifiedRecord(t *testing.T) {
	r := newCIRig(t)
	now := time.Now().UTC()
	r.svc.SetClock(func() time.Time { return now })
	r.svc.SetUnverifiedRefusalStore(r.repo)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	raw := r.idp.token(t, cfg.Audience, "acme/api", "main", "7777777777777777777777777777777777777777", nil)
	parsed, _, err := jwtv5.NewParser().ParseUnverified(raw, jwtv5.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwtv5.MapClaims{}
	for k, v := range parsed.Claims.(jwtv5.MapClaims) {
		claims[k] = v
	}
	claims["iss"] = r.idp.url + "/gitlab"
	slashed := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	slashed.Header["kid"] = parsed.Header["kid"]
	tok, err := slashed.SignedString(r.idp.key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []shared.ID{r.tenant, r.tenant, r.tenant, r.other} {
		resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": tenant.String(), "id_token": tok})
		if resp.StatusCode != http.StatusUnauthorized || out["code"] != "CI_TOKEN_NOT_TRUSTED" {
			t.Fatalf("unknown issuer: %d %v", resp.StatusCode, out)
		}
	}
	var audited int
	_ = r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs WHERE tenant_id = $1
		AND action = 'ci_run.token_refused'`, r.tenant.String()).Scan(&audited)
	if audited != 0 {
		t.Fatalf("an unverified refusal reached the tenant audit log: %d", audited)
	}
	list, configs, err := r.svc.UnverifiedRefusals(context.Background(), r.tenant)
	if err != nil || len(list) != 1 || list[0].Issuer != r.idp.url+"/gitlab" || list[0].Reason != cirunapp.UnverifiedNoConfiguration ||
		list[0].Count != 1 || len(configs) != 1 {
		t.Fatalf("unverified records: %+v %v", list, err)
	}
	if near, diff := cirunapp.NearestIssuer(list[0].Issuer, []string{configs[0].Issuer}); near != r.idp.url || diff != cirunapp.IssuerDiffPath {
		t.Fatalf("nearest issuer: %q %q", near, diff)
	}
	if other, _, _ := r.svc.UnverifiedRefusals(context.Background(), r.other); len(other) != 0 {
		t.Fatalf("a tenant without a trust configuration got a record: %+v", other)
	}
	now = now.Add(time.Minute)
	_, _ = r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": tok})
	if list, _, _ = r.svc.UnverifiedRefusals(context.Background(), r.tenant); len(list) != 1 || list[0].Count != 4 {
		t.Fatalf("after the throttle: %+v", list)
	}

	// Keys unavailable: a key id the platform has not fetched.
	rotated := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, parsed.Claims)
	rotated.Header["kid"] = "k-rotated"
	rtok, err := rotated.SignedString(r.idp.key)
	if err != nil {
		t.Fatal(err)
	}
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": rtok})
	details, _ := out["details"].(map[string]any)
	if resp.StatusCode != http.StatusServiceUnavailable || details["cause"] != cirunapp.IssuerCauseKeyNotFound {
		t.Fatalf("keys unavailable: %d %v", resp.StatusCode, out)
	}
	list, _, _ = r.svc.UnverifiedRefusals(context.Background(), r.tenant)
	found := false
	for _, u := range list {
		if u.Reason == cirunapp.UnverifiedKeysUnavailable && u.Cause == cirunapp.IssuerCauseKeyNotFound && u.Issuer == r.idp.url {
			found = true
		}
	}
	if !found {
		t.Fatalf("keys unavailable not recorded: %+v", list)
	}
}

// The store keeps at most MaxUnverifiedRefusals per tenant. A full tenant
// takes no new record while its records are recent (nothing is pushed out),
// and takes one in place of a record not seen for the retention period.
func TestCIRefusal_UnverifiedBounded(t *testing.T) {
	r := newCIRig(t)
	r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	ctx := context.Background()
	base := time.Now().UTC()
	record := func(i int, at time.Time) {
		t.Helper()
		if err := r.repo.RecordUnverifiedRefusal(ctx, cirun.UnverifiedRefusal{TenantID: r.tenant,
			Issuer: fmt.Sprintf("https://ci%02d.example.com", i), Reason: cirunapp.UnverifiedNoConfiguration,
			LastSeen: at, Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// The first record is old; the others are recent.
	record(0, base.Add(-cirun.UnverifiedRefusalRetention-time.Hour))
	for i := 1; i < cirun.MaxUnverifiedRefusals; i++ {
		record(i, base.Add(time.Duration(i)*time.Second))
	}
	record(50, base.Add(time.Minute)) // replaces the old record
	record(51, base.Add(time.Minute)) // full of recent records: not kept
	list, err := r.repo.ListUnverifiedRefusals(ctx, r.tenant)
	if err != nil || len(list) != cirun.MaxUnverifiedRefusals {
		t.Fatalf("bounded list: %d %v", len(list), err)
	}
	issuers := map[string]bool{}
	for _, u := range list {
		issuers[u.Issuer] = true
	}
	if issuers["https://ci00.example.com"] || !issuers["https://ci50.example.com"] || issuers["https://ci51.example.com"] ||
		!issuers["https://ci01.example.com"] {
		t.Fatalf("records kept: %v", issuers)
	}
}

// Review finding R1: a tenant full of recent no_configuration records (caller
// chosen issuers) must still get the keys_unavailable and not_verified records
// of its real issuer: they are not part of the bound.
func TestCIRefusal_UnverifiedRealIssuerRecordsAreNeverStarved(t *testing.T) {
	r := newCIRig(t)
	r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < cirun.MaxUnverifiedRefusals; i++ {
		if err := r.repo.RecordUnverifiedRefusal(ctx, cirun.UnverifiedRefusal{TenantID: r.tenant,
			Issuer: fmt.Sprintf("https://ci%02d.example.com", i), Reason: cirunapp.UnverifiedNoConfiguration,
			LastSeen: base, Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	for _, reason := range []string{cirunapp.UnverifiedKeysUnavailable, cirunapp.UnverifiedNotVerified} {
		if err := r.repo.RecordUnverifiedRefusal(ctx, cirun.UnverifiedRefusal{TenantID: r.tenant, Issuer: r.idp.url,
			Reason: reason, LastSeen: base, Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := r.repo.ListUnverifiedRefusals(ctx, r.tenant)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, u := range list {
		got[u.Reason]++
	}
	if got[cirunapp.UnverifiedNoConfiguration] != cirun.MaxUnverifiedRefusals || got[cirunapp.UnverifiedKeysUnavailable] != 1 ||
		got[cirunapp.UnverifiedNotVerified] != 1 {
		t.Fatalf("records by reason: %v", got)
	}
}

// Review finding: for no_configuration the stored issuer was whatever the
// anonymous token claimed, so 20 made-up issuers pushed a real record (a
// mistyped issuer) out and chose the text administrators read. An issuer not
// close to a configured one is now recorded as "another issuer" (one row),
// and the real record stays.
func TestCIRefusal_JunkIssuersDoNotEvict(t *testing.T) {
	r := newCIRig(t)
	now := time.Now().UTC()
	r.svc.SetClock(func() time.Time { return now })
	r.svc.SetUnverifiedRefusalStore(r.repo)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	withIssuer := func(iss string) string {
		return r.idp.token(t, cfg.Audience, "acme/api", "main", "7777777777777777777777777777777777777777", map[string]any{"iss": iss})
	}
	send := func(tok string) {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": tok}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("exchange: %d %v", resp.StatusCode, out)
		}
	}
	mistyped := r.idp.url + "/gitlab"
	send(withIssuer(mistyped))
	for i := 0; i < 25; i++ {
		now = now.Add(time.Second)
		send(withIssuer(fmt.Sprintf("https://junk%02d.example.org/oidc", i)))
		send(withIssuer(fmt.Sprintf("https://junk%02d.example.org", i))) // pathless: same (empty) path as the configured issuer
	}
	list, _, err := r.svc.UnverifiedRefusals(context.Background(), r.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var real, other int
	for _, u := range list {
		switch u.Issuer {
		case mistyped:
			real++
		case "":
			other++
		default:
			t.Errorf("a made-up issuer was stored: %q", u.Issuer)
		}
	}
	if real != 1 || other != 1 || len(list) != 2 {
		t.Fatalf("records: %+v", list)
	}
}

// Review finding: a verified token no configuration admits got the rule
// kinds of the organization's configurations (details.reasons) whatever the
// issuer. On a hosted issuer anyone can mint a verified token, so the job
// gets the generic refusal there; a self-managed issuer keeps the detail.
func TestCIRefusal_SharedIssuerGetsGenericMessage(t *testing.T) {
	r := newProviderRig(t)
	gh := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	tok := r.idp.sign(t, map[string]any{
		"iss": cirun.GitHubIssuer, "aud": gh.Audience, "sub": "repo:stranger/tool:ref:refs/heads/main",
		"repository": "stranger/tool", "repository_id": "5150", "repository_owner": "stranger", "repository_owner_id": "88",
		"ref": "refs/heads/main", "sha": "3333333333333333333333333333333333333333", "event_name": "push",
		"run_id": "1", "run_attempt": "1", "jti": shared.NewID().String(),
		"job_workflow_ref": "stranger/tool/.github/workflows/scan.yml@refs/heads/main",
	}, nil)
	code, out := r.exchangeWith(r.tenant, tok, nil)
	msg, _ := out["message"].(string)
	if code != http.StatusUnauthorized || out["code"] != "CI_TOKEN_NOT_TRUSTED" || out["details"] != nil ||
		strings.Contains(msg, "organizations or groups it lists") || strings.Contains(msg, "stranger") {
		t.Fatalf("hosted issuer refusal told the rule: %d %v", code, out)
	}
	// The administrator still sees the reason.
	list, err := r.svc.RecentRefusals(context.Background(), r.tenant, 1)
	if err != nil || len(list) != 1 || len(list[0].Configs) != 1 || list[0].Configs[0].Code != cirun.RefuseOwner {
		t.Fatalf("refusal record: %+v %v", list, err)
	}

	// The same refusal on a self-managed GitLab keeps the detail.
	const selfManaged = "https://gitlab.example.com"
	gl := r.trustFor(r.tenant, cirun.ProviderGitLab, selfManaged, cirun.Rules{Owners: []string{"acme"}})
	gtok := r.idp.sign(t, map[string]any{
		"iss": selfManaged, "aud": gl.Audience, "sub": "project_path:stranger/tool:ref_type:branch:ref:main",
		"project_path": "stranger/tool", "project_id": "61", "namespace_path": "stranger", "namespace_id": "62",
		"ref": "main", "ref_type": "branch", "sha": "4444444444444444444444444444444444444444",
		"pipeline_id": "1", "pipeline_source": "push", "jti": shared.NewID().String(),
	}, nil)
	code, out = r.exchangeWith(r.tenant, gtok, nil)
	msg, _ = out["message"].(string)
	details, _ := out["details"].(map[string]any)
	if code != http.StatusUnauthorized || !strings.Contains(msg, "organizations or groups it lists") || details == nil ||
		!strings.Contains(fmt.Sprint(details["reasons"]), cirun.RefuseOwner) {
		t.Fatalf("self-managed refusal lost its detail: %d %v", code, out)
	}
}

// Review finding: the one-click fix adds a value only from a refusal by that
// configuration's pipeline definitions or branches rule. A refusal by the
// owner rule (the token is not the organization's) cannot add anything.
func TestCIRefusal_AllowRefusesOtherRules(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	raw := r.idp.token(t, cfg.Audience, "evil/api", "release", "5555555555555555555555555555555555555555", nil)
	if code, _ := r.exchange(r.tenant, raw); code != http.StatusUnauthorized {
		t.Fatalf("owner refusal admitted: %d", code)
	}
	list, err := r.svc.RecentRefusals(context.Background(), r.tenant, 1)
	if err != nil || len(list) != 1 || list[0].Configs[0].Code != cirun.RefuseOwner {
		t.Fatalf("refusal: %+v %v", list, err)
	}
	if _, _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, shared.MustIDFromString(list[0].ID),
		cirunapp.Actor{Email: "admin@acme.test"}); !errors.Is(err, cirunapp.ErrAllowNotApplicable) {
		t.Fatalf("owner_not_allowed refusal allowed: %v", err)
	}
	// Another configuration than the one that refused cannot take it either.
	cfg2 := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	if _, _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg2.ID, shared.MustIDFromString(list[0].ID),
		cirunapp.Actor{Email: "admin@acme.test"}); !errors.Is(err, cirunapp.ErrAllowNotApplicable) {
		t.Fatalf("another configuration took the refusal: %v", err)
	}
}

// Review finding (low): the 503 told an anonymous caller the class of the
// failure. On a hosted issuer the class is withheld (the administrator's
// record keeps it); a self-managed issuer keeps it (TestCIRefusal_UnverifiedRecord).
func TestCIRefusal_SharedIssuerUnavailableWithholdsCause(t *testing.T) {
	r := newProviderRig(t)
	r.svc.SetUnverifiedRefusalStore(r.repo)
	gh := r.trustFor(r.tenant, cirun.ProviderGitHub, cirun.GitHubIssuer, cirun.Rules{Owners: []string{"acme"}})
	claims := jwtv5.MapClaims{
		"iss": cirun.GitHubIssuer, "aud": gh.Audience, "sub": "repo:acme/api:ref:refs/heads/main",
		"repository": "acme/api", "repository_id": "4242", "repository_owner": "acme", "repository_owner_id": "77",
		"ref": "refs/heads/main", "sha": "6666666666666666666666666666666666666666", "jti": shared.NewID().String(),
		"iat": time.Now().Unix(), "nbf": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	rotated := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	rotated.Header["kid"] = "k-rotated"
	tok, err := rotated.SignedString(r.idp.key)
	if err != nil {
		t.Fatal(err)
	}
	code, out := r.exchangeWith(r.tenant, tok, nil)
	if code != http.StatusServiceUnavailable || out["details"] != nil || strings.Contains(fmt.Sprint(out["message"]), "signing keys: the") {
		t.Fatalf("hosted issuer 503: %d %v", code, out)
	}
	list, _, _ := r.svc.UnverifiedRefusals(context.Background(), r.tenant)
	if len(list) != 1 || list[0].Cause != cirunapp.IssuerCauseKeyNotFound {
		t.Fatalf("administrator record: %+v", list)
	}
}
