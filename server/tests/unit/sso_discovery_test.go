package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Email-first sign-in: a claimed domain with SSO routes to its organization;
// everything else answers the same "password" shape.

type fakeDomainOwners struct {
	owners map[string]shared.ID
	err    error
}

func (f fakeDomainOwners) OwnerOfDomain(_ context.Context, domain string) (shared.ID, bool, error) {
	if f.err != nil {
		return shared.ID{}, false, f.err
	}
	id, ok := f.owners[domain]
	return id, ok, nil
}

func discoveryFixture(t *testing.T) (*auth.SSOService, fakeDomainOwners) {
	t.Helper()
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	withSSO := createTestTenant("acme")
	noSSO := createTestTenant("beta")
	tenantRepo.addTenant(withSSO)
	tenantRepo.addTenant(noSSO)
	p := createTestProvider(withSSO.ID().String(), identityprovider.ProviderOkta, true)
	ipRepo.providers[p.ID()] = p
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())
	owners := fakeDomainOwners{owners: map[string]shared.ID{"acme.com": withSSO.ID(), "beta.com": noSSO.ID()}}
	svc.SetDomainOwnerLookup(owners)
	svc.SetDiscoveryKey([]byte("discovery-test-key"))
	return svc, owners
}

func TestDiscover(t *testing.T) {
	svc, _ := discoveryFixture(t)
	ctx := context.Background()
	// A claimed domain with SSO answers an opaque reference, never the
	// slug; the reference resolves to the organization server-side.
	for _, email := range []string{"anyone@acme.com", "Someone@ACME.com"} {
		got := svc.Discover(ctx, email)
		if got.Next != auth.DiscoverNextSSO || got.Org == "" || got.Org == "acme" || strings.Contains(got.Org, "acme") {
			t.Fatalf("Discover(%q) = %+v: must route to SSO with an opaque reference", email, got)
		}
		if slug := svc.ResolveOrg(ctx, got.Org); slug != "acme" {
			t.Fatalf("the reference must resolve to the organization, got %q", slug)
		}
	}
	cases := map[string]auth.DiscoverResult{
		"x@beta.com":          {Next: auth.DiscoverNextPassword}, // claimed, but no SSO provider
		"x@unclaimed.example": {Next: auth.DiscoverNextPassword},
		"x@gmail.com":         {Next: auth.DiscoverNextPassword},
		"not-an-email":        {Next: auth.DiscoverNextPassword},
		"":                    {Next: auth.DiscoverNextPassword},
		"trailing-at@":        {Next: auth.DiscoverNextPassword},
	}
	for email, want := range cases {
		if got := svc.Discover(ctx, email); got != want {
			t.Errorf("Discover(%q) = %+v, want %+v", email, got, want)
		}
	}
}

// References cannot be forged or altered, and a plain slug still works.
func TestResolveOrg(t *testing.T) {
	svc, _ := discoveryFixture(t)
	ctx := context.Background()
	ref := svc.Discover(ctx, "a@acme.com").Org
	if svc.ResolveOrg(ctx, "acme") != "acme" {
		t.Fatal("a slug passes through")
	}
	if got := svc.ResolveOrg(ctx, ref[:len(ref)-3]+"abc"); got != "" {
		t.Fatalf("an altered reference must match nothing, got %q", got)
	}
	other, _ := discoveryFixture(t)
	other.SetDiscoveryKey([]byte("another-key"))
	if got := other.ResolveOrg(ctx, ref); got != "" {
		t.Fatalf("a reference signed with another key must match nothing, got %q", got)
	}
	nokey, _ := discoveryFixture(t)
	nokey.SetDiscoveryKey(nil)
	if got := nokey.Discover(ctx, "a@acme.com"); got.Next != auth.DiscoverNextPassword {
		t.Fatalf("without a key discovery answers password, got %+v", got)
	}
}

func TestDiscover_FailsToPassword(t *testing.T) {
	svc, _ := discoveryFixture(t)
	svc.SetDomainOwnerLookup(fakeDomainOwners{err: errors.New("db down")})
	if got := svc.Discover(context.Background(), "a@acme.com"); got.Next != auth.DiscoverNextPassword || got.Org != "" {
		t.Fatalf("a lookup error answers password, got %+v", got)
	}
	unwired, _ := discoveryFixture(t)
	unwired.SetDomainOwnerLookup(nil)
	if got := unwired.Discover(context.Background(), "a@acme.com"); got.Next != auth.DiscoverNextPassword {
		t.Fatalf("without a lookup discovery answers password, got %+v", got)
	}
}

// The HTTP answer has the same shape for every email, and the email travels
// in the body.
func TestDiscoverHandler_SameShape(t *testing.T) {
	svc, _ := discoveryFixture(t)
	h := handler.NewSSOHandler(svc, logger.NewNop())
	post := func(email string) map[string]any {
		b, _ := json.Marshal(map[string]string{"email": email})
		rec := httptest.NewRecorder()
		h.Discover(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/discover", bytes.NewReader(b)))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", email, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("the answer must not be cached")
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return body
	}
	sso, unknown := post("a@acme.com"), post("a@nobody.example")
	if len(sso) != 2 || len(unknown) != 2 {
		t.Fatalf("both answers carry exactly next and org: %v / %v", sso, unknown)
	}
	if unknown["next"] != "password" || unknown["org"] != "" || sso["next"] != "sso" || sso["org"] == "acme" || sso["org"] == "" {
		t.Fatalf("unexpected answers %v / %v", sso, unknown)
	}
}
