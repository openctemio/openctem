package mcpoauth_test

// A credential change ends the person's connected applications in every
// organization, and only theirs. DB-gated like service_db_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRevokeUserGrantsEndsOneUserInEveryTenant(t *testing.T) {
	h := newHarness(t)
	victim := h.member(h.tenant, "owner")
	h.join(h.other, victim.String(), "member")
	bystander := h.member(h.tenant, "owner")

	tok := func(user shared.ID, tenant string) *mcpoauth.TokenResponse {
		t.Helper()
		code := h.approve(user, tenant, authorizeQuery(nil))
		res, oerr := h.exchange(code, verifier, nil)
		if oerr != nil {
			t.Fatalf("exchange: %v", oerr)
		}
		return res
	}
	v1, v2, b1 := tok(victim, h.tenant), tok(victim, h.other), tok(bystander, h.tenant)
	// An approved code not yet redeemed must die too.
	pendingCode := h.approve(victim, h.tenant, authorizeQuery(nil))

	n, err := h.svc.RevokeUserGrants(context.Background(), victim)
	if err != nil || n != 2 {
		t.Fatalf("RevokeUserGrants: n=%d err=%v, want 2 grants", n, err)
	}
	for name, res := range map[string]*mcpoauth.TokenResponse{"tenant A": v1, "tenant B": v2} {
		if _, err := h.principal(res.AccessToken); !errors.Is(err, mcpoauth.ErrInvalidToken) {
			t.Errorf("%s access token still works: %v", name, err)
		}
		if _, oerr := h.refresh(res.RefreshToken, nil); oerr == nil || oerr.Code != "invalid_grant" {
			t.Errorf("%s refresh after revocation: %v, want invalid_grant", name, oerr)
		}
	}
	if _, oerr := h.exchange(pendingCode, verifier, nil); oerr == nil {
		t.Error("an approved code redeemed after the credential change")
	}
	// The other user's connection is untouched.
	if _, err := h.principal(b1.AccessToken); err != nil {
		t.Errorf("bystander's grant was revoked: %v", err)
	}
	if _, oerr := h.refresh(b1.RefreshToken, nil); oerr != nil {
		t.Errorf("bystander's refresh failed: %v", oerr)
	}
}

// A membership whose end date passed stops MCP tokens at once, before the
// sweeper suspends it.
func TestExpiredMembershipStopsMCPToken(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	code := h.approve(user, h.tenant, authorizeQuery(nil))
	tok, oerr := h.exchange(code, verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, err := h.principal(tok.AccessToken); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	h.exec(`UPDATE tenant_members SET expires_at = $2 WHERE user_id = $1`, user.String(), time.Now().Add(-time.Minute))
	if _, err := h.principal(tok.AccessToken); !errors.Is(err, mcpoauth.ErrInvalidToken) {
		t.Fatalf("expired membership's token accepted: %v", err)
	}
}
