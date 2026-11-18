package integration

import (
	"context"
	"errors"
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

	// Another tenant cannot touch the configuration.
	if _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.other, cfg.ID, cirunapp.AllowWorkflowRef, value,
		cirunapp.Actor{Email: "admin@other.test"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant allow: %v", err)
	}
	if _, _, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, "owner", "evil",
		cirunapp.Actor{Email: "admin@acme.test"}); !errors.Is(err, cirunapp.ErrAllowKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	next, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, cirunapp.AllowWorkflowRef, value,
		cirunapp.Actor{Email: "admin@acme.test"})
	if err != nil || !changed || len(next.Rules.WorkflowRefs) != 2 {
		t.Fatalf("allow: %v %v %+v", err, changed, next)
	}
	if _, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, cirunapp.AllowWorkflowRef, value,
		cirunapp.Actor{Email: "admin@acme.test"}); err != nil || changed {
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
	if _, changed, err := r.svc.AllowInTrustConfig(context.Background(), r.tenant, cfg.ID, cirunapp.AllowRef, "release",
		cirunapp.Actor{Email: "admin@acme.test"}); err != nil || !changed {
		t.Fatalf("allow ref: %v %v", err, changed)
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

// The store keeps at most MaxUnverifiedRefusals per tenant, newest first.
func TestCIRefusal_UnverifiedBounded(t *testing.T) {
	r := newCIRig(t)
	r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	base := time.Now().UTC()
	for i := 0; i < cirun.MaxUnverifiedRefusals+5; i++ {
		if err := r.repo.RecordUnverifiedRefusal(context.Background(), cirun.UnverifiedRefusal{TenantID: r.tenant,
			Issuer: "https://ci" + string(rune('a'+i)) + ".example.com", Reason: cirunapp.UnverifiedNoConfiguration,
			LastSeen: base.Add(time.Duration(i) * time.Second), Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := r.repo.ListUnverifiedRefusals(context.Background(), r.tenant)
	if err != nil || len(list) != cirun.MaxUnverifiedRefusals || !strings.HasPrefix(list[0].Issuer, "https://ci"+string(rune('a'+cirun.MaxUnverifiedRefusals+4))) {
		t.Fatalf("bounded list: %d %v (first %+v)", len(list), err, list[0])
	}
}
