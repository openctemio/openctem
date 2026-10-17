package routes

// Research 170 (assets authz audit), fork 3. A request with a tenant but no
// user — what the API key authenticator produces for a key whose user_id is
// NULL (an "organization" key, research doc 15 L-21) — resolves to NO data
// scope at all: datascope.Enforcer.ResolveFor returns nil for c.UserID == ""
// even when c.APIKey is set. Such a key therefore reads every asset of the
// tenant, including private bounty-program assets hidden from administrators,
// while a key bound to a member is narrowed to that member's scope rows.
//
// These tests FAIL on develop b9f14be96: they document the bug.

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestAuthz170F3_UserlessAPIKey_ResolvesUnrestricted: the enforcer decision.
func TestAuthz170F3_UserlessAPIKey_ResolvesUnrestricted(t *testing.T) {
	h := newDSHarness(t)
	scope, err := h.enforcer.ResolveFor(context.Background(), h.tenant, datascope.Caller{APIKey: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope == nil {
		t.Errorf("a user-less API key resolves to a nil (unrestricted) data scope; want a restricted scope (fail closed)")
	}
}

// TestAuthz170F3_UserlessAPIKey_ReadsOutOfScopeAsset: over the real routes, a
// request with no user and no admin flag reads an asset sub-resource that a
// scoped member gets 404 for.
func TestAuthz170F3_UserlessAPIKey_ReadsOutOfScopeAsset(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/assets/" + h.assetB.String() + "/services/"
	if status, _ := h.do(h.memberA, false, http.MethodGet, path, nil); status != http.StatusNotFound {
		t.Fatalf("precondition: scoped member GET out-of-scope = %d, want 404", status)
	}
	// shared.ID{} = no user in the context (dsAuth leaves UserIDKey unset).
	if status, body := h.do(shared.ID{}, false, http.MethodGet, path, nil); status != http.StatusNotFound {
		t.Errorf("user-less caller GET %s = %d, want 404 (body %.200s)", path, status, body)
	}
}
