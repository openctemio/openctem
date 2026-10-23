package scim

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
func (f *fakeTokenRepo) TouchLastUsed(_ context.Context, _ shared.ID, id shared.ID, at time.Time) error {
	if t, ok := f.byID[id]; ok && t.IsActive() {
		t.TouchLastUsed(at)
	}
	return nil
}

func (f *fakeTokenRepo) ShortenExpiry(_ context.Context, tenantID, id shared.ID, at time.Time) error {
	t, ok := f.byID[id]
	if !ok || t.TenantID() != tenantID || !t.IsActive() {
		return scimtoken.ErrNotFound
	}
	t.ExpireBy(at)
	return nil
}

func newTokenSvc() (*TokenService, *fakeTokenRepo) {
	repo := newFakeTokenRepo()
	return NewTokenService(repo, "test-pepper", logger.NewNop()), repo
}

func TestTokenMintAndAuthenticate(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantID := shared.NewID()

	res, err := svc.Mint(context.Background(), tenantID, "okta", nil, 90)
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
	res, _ := svc.Mint(context.Background(), tenantID, "t", nil, 90)

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
	res, _ := svc.Mint(context.Background(), tenantID, "t", nil, 90)

	if err := svc.Revoke(context.Background(), tenantID, res.Token.ID()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Simulate the touch from an in-flight authentication that loaded the token
	// before the revoke landed.
	if err := repo.TouchLastUsed(context.Background(), tenantID, res.Token.ID(), time.Now()); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err == nil {
		t.Fatal("revoked token must stay revoked after a concurrent last-used touch")
	}
}

func TestTokenRevokeIsTenantScoped(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	res, _ := svc.Mint(context.Background(), tenantA, "t", nil, 90)

	// Tenant B must not be able to revoke tenant A's token.
	if err := svc.Revoke(context.Background(), tenantB, res.Token.ID()); err == nil {
		t.Error("cross-tenant revoke must fail")
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err != nil {
		t.Error("token should still be valid after a failed cross-tenant revoke")
	}
}

// Encryption-key rotation: a token minted under the old pepper keeps
// authenticating while the old key is listed as previous.
func TestTokenService_PreviousPepperDuringKeyRotation(t *testing.T) {
	repo := newFakeTokenRepo()
	old := NewTokenService(repo, "old-pepper", logger.NewNop())
	minted, err := old.Mint(context.Background(), shared.NewID(), "pre-rotation", nil, 90)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rotated := NewTokenService(repo, "new-pepper", logger.NewNop())
	if _, err := rotated.Authenticate(context.Background(), minted.Plaintext); err == nil {
		t.Fatal("without the previous pepper the old token must not authenticate")
	}
	rotated.SetLegacyPeppers("old-pepper")
	if _, err := rotated.Authenticate(context.Background(), minted.Plaintext); err != nil {
		t.Fatalf("with the previous pepper listed the old token must authenticate: %v", err)
	}
}

// RehashKey makes the fake a TokenRehasher (compare-and-swap).
func (f *fakeTokenRepo) RehashKey(_ context.Context, id shared.ID, oldHash, newHash string) (bool, error) {
	t, ok := f.byID[id]
	if !ok || f.byHash[oldHash] != t {
		return false, nil
	}
	delete(f.byHash, oldHash)
	f.byHash[newHash] = t
	return true, nil
}

// A token that authenticates through the previous pepper is re-hashed with
// the current one and keeps working once the previous key is removed.
func TestTokenService_PreviousPepperTokenIsRehashed(t *testing.T) {
	repo := newFakeTokenRepo()
	minted, err := NewTokenService(repo, "old-pepper", logger.NewNop()).Mint(context.Background(), shared.NewID(), "pre-rotation", nil, 90)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rotated := NewTokenService(repo, "new-pepper", logger.NewNop())
	rotated.SetLegacyPeppers("old-pepper")
	if _, err := rotated.Authenticate(context.Background(), minted.Plaintext); err != nil {
		t.Fatalf("authenticate through the previous pepper: %v", err)
	}
	if _, err := NewTokenService(repo, "new-pepper", logger.NewNop()).Authenticate(context.Background(), minted.Plaintext); err != nil {
		t.Fatalf("a re-hashed token must authenticate without the previous pepper: %v", err)
	}
}

// A token needs a lifetime of 1 to 365 days.
func TestTokenMint_LifetimeRequiredAndBounded(t *testing.T) {
	svc, _ := newTokenSvc()
	for _, days := range []int{0, -1, 366} {
		if _, err := svc.Mint(context.Background(), shared.NewID(), "t", nil, days); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%d days: want a validation error, got %v", days, err)
		}
	}
	res, err := svc.Mint(context.Background(), shared.NewID(), "t", nil, 365)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(res.Token.ExpiresAt()); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Fatalf("expires in %s, want 365 days", d)
	}
}

// An expired token answers like an unknown one.
func TestTokenAuthenticate_ExpiredRefused(t *testing.T) {
	svc, _ := newTokenSvc()
	res, err := svc.Mint(context.Background(), shared.NewID(), "t", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); err != nil {
		t.Fatalf("fresh token: %v", err)
	}
	svc.now = func() time.Time { return time.Now().UTC().Add(25 * time.Hour) }
	if _, err := svc.Authenticate(context.Background(), res.Plaintext); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Fatalf("expired token: want ErrNotFound, got %v", err)
	}
}

// Rotation: the replacement works at once, the old token keeps working for
// the overlap and then stops; the lifetime carries over when not given.
func TestTokenRotate_OverlapThenOldStops(t *testing.T) {
	svc, _ := newTokenSvc()
	tenantID := shared.NewID()
	old, err := svc.Mint(context.Background(), tenantID, "okta", nil, 180)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := svc.Rotate(context.Background(), tenantID, old.Token.ID(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Token.Name() != "okta" || rot.Plaintext == old.Plaintext {
		t.Fatalf("replacement %q", rot.Token.Name())
	}
	if d := time.Until(rot.Token.ExpiresAt()); d < 179*24*time.Hour || d > 181*24*time.Hour {
		t.Fatalf("replacement expires in %s, want the old lifetime (180 days)", d)
	}
	if d := time.Until(rot.ReplacedExpiresAt); d > scimtoken.RotationOverlap || d < scimtoken.RotationOverlap-time.Minute {
		t.Fatalf("old token cut off in %s, want %s", d, scimtoken.RotationOverlap)
	}
	for name, p := range map[string]string{"old": old.Plaintext, "new": rot.Plaintext} {
		if _, err := svc.Authenticate(context.Background(), p); err != nil {
			t.Fatalf("%s token during the overlap: %v", name, err)
		}
	}
	svc.now = func() time.Time { return time.Now().UTC().Add(scimtoken.RotationOverlap + time.Minute) }
	if _, err := svc.Authenticate(context.Background(), old.Plaintext); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Fatalf("old token after the overlap: %v", err)
	}
	if _, err := svc.Authenticate(context.Background(), rot.Plaintext); err != nil {
		t.Fatalf("new token after the overlap: %v", err)
	}
}

// Another tenant's, a revoked and an expired token cannot be rotated.
func TestTokenRotate_Refusals(t *testing.T) {
	svc, repo := newTokenSvc()
	tenantID := shared.NewID()
	tok, _ := svc.Mint(context.Background(), tenantID, "t", nil, 30)
	if _, err := svc.Rotate(context.Background(), shared.NewID(), tok.Token.ID(), nil, 0); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Errorf("other tenant: %v", err)
	}
	if _, err := svc.Rotate(context.Background(), tenantID, tok.Token.ID(), nil, 400); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("lifetime 400 days: %v", err)
	}
	revoked, _ := svc.Mint(context.Background(), tenantID, "r", nil, 30)
	if err := svc.Revoke(context.Background(), tenantID, revoked.Token.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Rotate(context.Background(), tenantID, revoked.Token.ID(), nil, 0); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Errorf("revoked: %v", err)
	}
	svc.now = func() time.Time { return time.Now().UTC().Add(31 * 24 * time.Hour) }
	if _, err := svc.Rotate(context.Background(), tenantID, tok.Token.ID(), nil, 0); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Errorf("expired: %v", err)
	}
	// No refused rotation minted anything.
	n := 0
	for _, t := range repo.byID {
		if t.TenantID() == tenantID {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d tokens after refusals, want 2", n)
	}
}
