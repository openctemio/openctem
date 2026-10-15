package integration

import (
	"context"
	"net/http"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

// A token signed with a key the platform has not fetched (the provider just
// rotated) is "retry later" (503, Retry-After), and nothing is claimed: the
// same job retries the same token once the keys are fetched.
func TestCIExchange_IssuerKeyRotationIsRetryable(t *testing.T) {
	r := newCIRig(t)
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}})
	raw := r.idp.token(t, cfg.Audience, "acme/api", "main", "7777777777777777777777777777777777777777", nil)
	parsed, _, err := jwtv5.NewParser().ParseUnverified(raw, jwtv5.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	rotated := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, parsed.Claims)
	rotated.Header["kid"] = "k-rotated"
	tok, err := rotated.SignedString(r.idp.key)
	if err != nil {
		t.Fatal(err)
	}
	resp, out := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(), "id_token": tok})
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || out["code"] != "CI_ISSUER_UNAVAILABLE" {
		t.Fatalf("unknown kid: %d %v (Retry-After %q)", resp.StatusCode, out, resp.Header.Get("Retry-After"))
	}
	var claimed int
	_ = r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM ci_oidc_replay WHERE jti = $1`, parsed.Claims.(jwtv5.MapClaims)["jti"]).Scan(&claimed)
	if claimed != 0 {
		t.Fatal("a token refused before verification was claimed")
	}
	// The original token (known kid) is admitted.
	if code, ex := r.exchange(r.tenant, raw); code != http.StatusCreated {
		t.Fatalf("known kid: %d %v", code, ex)
	}
}
