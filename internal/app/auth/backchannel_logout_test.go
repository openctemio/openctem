package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/api/internal/config"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes ---------------------------------------------------------------

type bcSessionRepo struct {
	sessiondom.Repository
	sessions []*sessiondom.Session
	updated  map[string]bool
}

func (r *bcSessionRepo) GetActiveByIDPSID(_ context.Context, issuer, sid string) ([]*sessiondom.Session, error) {
	var out []*sessiondom.Session
	for _, s := range r.sessions {
		if s.IDPIssuer() == issuer && s.IDPSID() == sid && s.IsActive() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *bcSessionRepo) GetActiveByIDPSub(_ context.Context, issuer, sub string) ([]*sessiondom.Session, error) {
	var out []*sessiondom.Session
	for _, s := range r.sessions {
		if s.IDPIssuer() == issuer && s.IDPSub() == sub && s.IsActive() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *bcSessionRepo) Update(_ context.Context, s *sessiondom.Session) error {
	if r.updated == nil {
		r.updated = map[string]bool{}
	}
	r.updated[s.ID().String()] = true
	return nil
}

type bcRefreshRepo struct {
	sessiondom.RefreshTokenRepository
	revoked map[string]bool
}

func (r *bcRefreshRepo) RevokeBySessionID(_ context.Context, id shared.ID) error {
	if r.revoked == nil {
		r.revoked = map[string]bool{}
	}
	r.revoked[id.String()] = true
	return nil
}

type bcIPRepo struct {
	identityproviderdom.Repository
	active []*identityproviderdom.IdentityProvider
}

func (r *bcIPRepo) ListActiveByProvider(_ context.Context, p identityproviderdom.Provider) ([]*identityproviderdom.IdentityProvider, error) {
	var out []*identityproviderdom.IdentityProvider
	for _, ip := range r.active {
		if ip.Provider() == p {
			out = append(out, ip)
		}
	}
	return out, nil
}

// --- harness -------------------------------------------------------------

type bcHarness struct {
	svc      *SSOService
	key      *rsa.PrivateKey
	sessRepo *bcSessionRepo
	rtRepo   *bcRefreshRepo
	iss      string
}

func newBCHarness(t *testing.T) *bcHarness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sessRepo := &bcSessionRepo{updated: map[string]bool{}}
	rtRepo := &bcRefreshRepo{revoked: map[string]bool{}}

	verifier := newOIDCVerifier(&http.Client{Timeout: 2 * time.Second}, logger.NewNop())
	// Seed the JWKS cache under the DERIVED Entra JWKS URL so keyForKID resolves
	// the test key without any network fetch.
	jwksURL := identityproviderdom.ProviderEntraID.JWKSURL(testTenantID)
	verifier.cache[jwksURL] = &jwksEntry{
		keys:      map[string]*rsa.PublicKey{testKID: &key.PublicKey},
		fetchedAt: time.Now(),
	}

	svc := &SSOService{
		ipRepo:           &bcIPRepo{},
		sessionRepo:      sessRepo,
		refreshTokenRepo: rtRepo,
		authConfig: config.AuthConfig{
			EntraSSO: config.EntraSSOConfig{
				Enabled:      true,
				ClientID:     testClientID,
				ClientSecret: "secret",
				TenantID:     testTenantID,
			},
		},
		logger:       logger.NewNop(),
		oidcVerifier: verifier,
	}
	return &bcHarness{svc: svc, key: key, sessRepo: sessRepo, rtRepo: rtRepo, iss: testIssuer(testTenantID)}
}

// seedSession adds an active federated session bound to (issuer, sid, sub).
func (h *bcHarness) seedSession(t *testing.T, sid, sub string) *sessiondom.Session {
	t.Helper()
	s, err := sessiondom.NewWithID(shared.NewID(), shared.NewID(), "tok-"+sid+sub, "", "", time.Hour)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	s.SetAuthMethod(sessiondom.AuthMethodSSO)
	s.SetFederatedBinding(h.iss, sid, sub)
	h.sessRepo.sessions = append(h.sessRepo.sessions, s)
	return s
}

func (h *bcHarness) sign(t *testing.T, claims jwtv5.MapClaims) string {
	t.Helper()
	return h.signWithKey(t, h.key, claims)
}

func (h *bcHarness) signWithKey(t *testing.T, key *rsa.PrivateKey, claims jwtv5.MapClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign logout_token: %v", err)
	}
	return signed
}

// validLogoutClaims returns a spec-valid logout_token claim set for this issuer.
func (h *bcHarness) validLogoutClaims(sid, sub string) jwtv5.MapClaims {
	c := jwtv5.MapClaims{
		"iss":    h.iss,
		"aud":    testClientID,
		"iat":    time.Now().Unix(),
		"jti":    "jti-" + sid + sub,
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
	if sid != "" {
		c["sid"] = sid
	}
	if sub != "" {
		c["sub"] = sub
	}
	return c
}

// --- tests ---------------------------------------------------------------

func TestBackChannelLogout_Valid_RevokesBySID(t *testing.T) {
	h := newBCHarness(t)
	sess := h.seedSession(t, "sid-1", "subject-1")
	other := h.seedSession(t, "sid-2", "subject-2") // must remain untouched

	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, h.validLogoutClaims("sid-1", "subject-1")))
	if err != nil {
		t.Fatalf("valid logout_token errored: %v", err)
	}
	if n != 1 {
		t.Fatalf("revoked=%d, want 1", n)
	}
	if !h.sessRepo.updated[sess.ID().String()] || !h.rtRepo.revoked[sess.ID().String()] {
		t.Fatalf("target session/refresh tokens not revoked")
	}
	if h.sessRepo.updated[other.ID().String()] {
		t.Fatalf("unrelated session was revoked")
	}
}

func TestBackChannelLogout_ForgedSignature_NoRevocation(t *testing.T) {
	h := newBCHarness(t)
	sess := h.seedSession(t, "sid-1", "subject-1")

	// Sign with a DIFFERENT key — signature will not verify against the cached JWKS.
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := h.signWithKey(t, attackerKey, h.validLogoutClaims("sid-1", "subject-1"))

	n, err := h.svc.BackChannelLogout(context.Background(), forged)
	if err == nil {
		t.Fatalf("forged token accepted")
	}
	if n != 0 || h.sessRepo.updated[sess.ID().String()] {
		t.Fatalf("forged token revoked a session (n=%d)", n)
	}
}

func TestBackChannelLogout_WrongAudience_Rejected(t *testing.T) {
	h := newBCHarness(t)
	sess := h.seedSession(t, "sid-1", "subject-1")
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["aud"] = "some-other-client"

	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 || h.sessRepo.updated[sess.ID().String()] {
		t.Fatalf("wrong aud accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_UnknownIssuer_Rejected(t *testing.T) {
	h := newBCHarness(t)
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["iss"] = testIssuer("99999999-9999-9999-9999-999999999999") // no configured provider
	// even signed correctly, no provider resolves this issuer → rejected
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 {
		t.Fatalf("unknown issuer accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_MissingEvents_Rejected(t *testing.T) {
	h := newBCHarness(t)
	sess := h.seedSession(t, "sid-1", "subject-1")
	c := h.validLogoutClaims("sid-1", "subject-1")
	delete(c, "events")

	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 || h.sessRepo.updated[sess.ID().String()] {
		t.Fatalf("missing events accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_WrongEventValue_Rejected(t *testing.T) {
	h := newBCHarness(t)
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["events"] = map[string]any{"http://schemas.openid.net/event/some-other-event": map[string]any{}}
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 {
		t.Fatalf("wrong event member accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_NoncePresent_Rejected(t *testing.T) {
	h := newBCHarness(t)
	sess := h.seedSession(t, "sid-1", "subject-1")
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["nonce"] = "should-not-be-here"

	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 || h.sessRepo.updated[sess.ID().String()] {
		t.Fatalf("logout_token with nonce accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_MissingSidAndSub_Rejected(t *testing.T) {
	h := newBCHarness(t)
	c := h.validLogoutClaims("", "") // neither sid nor sub
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 {
		t.Fatalf("logout_token without sid/sub accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_StaleIat_Rejected(t *testing.T) {
	h := newBCHarness(t)
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["iat"] = time.Now().Add(-30 * time.Minute).Unix() // older than logoutTokenMaxAge
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 {
		t.Fatalf("stale iat accepted (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_SubOnly_RevokesAllUserSessions(t *testing.T) {
	h := newBCHarness(t)
	// Two sessions for the same subject (different sids), plus an unrelated one.
	s1 := h.seedSession(t, "sid-a", "subject-1")
	s2 := h.seedSession(t, "sid-b", "subject-1")
	other := h.seedSession(t, "sid-c", "subject-2")

	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, h.validLogoutClaims("", "subject-1")))
	if err != nil {
		t.Fatalf("sub-only logout errored: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked=%d, want 2", n)
	}
	if !h.sessRepo.updated[s1.ID().String()] || !h.sessRepo.updated[s2.ID().String()] {
		t.Fatalf("not all of the subject's sessions were revoked")
	}
	if h.sessRepo.updated[other.ID().String()] {
		t.Fatalf("a different subject's session was revoked")
	}
}

func TestBackChannelLogout_CrossProvider_NoRevocation(t *testing.T) {
	h := newBCHarness(t)
	// Session bound to a DIFFERENT issuer (different directory) than the env config.
	otherIss := testIssuer("22222222-2222-2222-2222-222222222222")
	s, err := sessiondom.NewWithID(shared.NewID(), shared.NewID(), "tok-x", "", "", time.Hour)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	s.SetAuthMethod(sessiondom.AuthMethodSSO)
	s.SetFederatedBinding(otherIss, "sid-1", "subject-1")
	h.sessRepo.sessions = append(h.sessRepo.sessions, s)

	// A logout_token for that other issuer: env only configured for testTenantID,
	// so no provider resolves the other issuer → rejected, nothing revoked.
	c := h.validLogoutClaims("sid-1", "subject-1")
	c["iss"] = otherIss
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, c))
	if err == nil || n != 0 || h.sessRepo.updated[s.ID().String()] {
		t.Fatalf("cross-provider logout revoked a session (err=%v n=%d)", err, n)
	}
}

func TestBackChannelLogout_UnknownSID_Success_ZeroRevoked(t *testing.T) {
	h := newBCHarness(t)
	h.seedSession(t, "sid-real", "subject-1")

	// Valid token but sid matches no session — must succeed with 0 revoked
	// (do not leak which sids exist).
	n, err := h.svc.BackChannelLogout(context.Background(), h.sign(t, h.validLogoutClaims("sid-ghost", "")))
	if err != nil {
		t.Fatalf("unknown sid should succeed: %v", err)
	}
	if n != 0 {
		t.Fatalf("revoked=%d, want 0", n)
	}
}

func TestBackChannelLogout_EmptyToken_Rejected(t *testing.T) {
	h := newBCHarness(t)
	if _, err := h.svc.BackChannelLogout(context.Background(), "   "); err == nil {
		t.Fatalf("empty logout_token accepted")
	}
}
