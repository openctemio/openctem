package scim

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/scimtoken"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeTokenRepo struct {
	byHash map[string]*scimtoken.ScimToken
	byID   map[shared.ID]*scimtoken.ScimToken
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{byHash: map[string]*scimtoken.ScimToken{}, byID: map[shared.ID]*scimtoken.ScimToken{}}
}

func (f *fakeTokenRepo) Create(_ context.Context, t *scimtoken.ScimToken) error {
	f.byHash[t.TokenHash()] = t
	f.byID[t.ID()] = t
	return nil
}
func (f *fakeTokenRepo) GetByHash(_ context.Context, hash string) (*scimtoken.ScimToken, error) {
	if t, ok := f.byHash[hash]; ok {
		return t, nil
	}
	return nil, scimtoken.ErrNotFound
}
func (f *fakeTokenRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scimtoken.ScimToken, error) {
	if t, ok := f.byID[id]; ok && t.TenantID() == tenantID {
		return t, nil
	}
	return nil, scimtoken.ErrNotFound
}
func (f *fakeTokenRepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*scimtoken.ScimToken, error) {
	var out []*scimtoken.ScimToken
	for _, t := range f.byID {
		if t.TenantID() == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}
func (f *fakeTokenRepo) Update(_ context.Context, t *scimtoken.ScimToken) error {
	f.byHash[t.TokenHash()] = t
	f.byID[t.ID()] = t
	return nil
}
func (f *fakeTokenRepo) TouchLastUsed(_ context.Context, id shared.ID, at time.Time) error {
	if t, ok := f.byID[id]; ok && t.IsActive() {
		t.TouchLastUsed(at)
	}
	return nil
}

func newTokenSvc() (*TokenService, *fakeTokenRepo) {
	repo := newFakeTokenRepo()
	return NewTokenService(repo, "test-pepper", logger.NewNop()), repo
}

func TestTokenMintAndAuthenticate(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantID := shared.NewID()

	res, err := svc.Mint(context.Background(), tenantID, "okta", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(res.Plaintext, "oct_scim_") {
		t.Errorf("plaintext should carry the oct_scim_ prefix, got %q", res.Plaintext)
	}

	tok, err := svc.Authenticate(context.Background(), res.Plaintext)
	if err != nil {
		t.Fatalf("authenticate valid token: %v", err)
	}
	if tok.TenantID() != tenantID {
		t.Errorf("token tenant = %s, want %s", tok.TenantID(), tenantID)
	}
}

func TestTokenAuthenticateRejectsBadAndRevoked(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantID := shared.NewID()
	res, _ := svc.Mint(context.Background(), tenantID, "t", nil)

	if _, err := svc.Authenticate(context.Background(), "oct_scim_bogus"); err == nil {
		t.Error("expected error for unknown token")
	}
	if _, err := svc.Authenticate(context.Background(), ""); err == nil {
		t.Error("expected error for empty token")
	}

	if err := svc.Revoke(context.Background(), tenantID, res.Token.ID()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestTokenTouchDoesNotResurrectRevoked(t *testing.T) {
	// A last-used touch racing with a revoke must never re-activate the token.
	svc, repo := newTokenSvc()
	tenantID := shared.NewID()
	res, _ := svc.Mint(context.Background(), tenantID, "t", nil)

	if err := svc.Revoke(context.Background(), tenantID, res.Token.ID()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Simulate the touch from an in-flight authentication that loaded the token
	// before the revoke landed.
	if err := repo.TouchLastUsed(context.Background(), res.Token.ID(), time.Now()); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err == nil {
		t.Fatal("revoked token must stay revoked after a concurrent last-used touch")
	}
}

func TestTokenRevokeIsTenantScoped(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	res, _ := svc.Mint(context.Background(), tenantA, "t", nil)

	// Tenant B must not be able to revoke tenant A's token.
	if err := svc.Revoke(context.Background(), tenantB, res.Token.ID()); err == nil {
		t.Error("cross-tenant revoke must fail")
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err != nil {
		t.Error("token should still be valid after a failed cross-tenant revoke")
	}
}
