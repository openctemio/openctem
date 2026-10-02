package auth

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A session is exempt from an organization's SSO enforcement and 2FA
// requirement only when that organization's own identity provider issued it.
// These tests pin where the issuing organization is recorded: the
// organization's OIDC callback stamps it, social OAuth never does.

// The OIDC callback for organization "acme" stamps the session as federated
// AND issued by acme's IdP, and nothing else.
func TestOIDCCallback_StampsIssuingTenant(t *testing.T) {
	var sessions []*sessiondom.Session
	res, _, _, err := runOktaCallbackRecording(t, "person@acme.io", map[string]bool{"acme.io": true}, true, &sessions)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("created %d sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if s.AuthMethod() != sessiondom.AuthMethodSSO {
		t.Fatalf("auth method = %q, want sso", s.AuthMethod())
	}
	if s.IDPTenantID().String() != res.TenantID {
		t.Fatalf("issuing tenant = %q, want the callback's tenant %q", s.IDPTenantID().String(), res.TenantID)
	}
	if !s.FederatedFor(res.TenantID) {
		t.Fatal("the session must count as an SSO sign-in of the issuing organization")
	}
	if s.FederatedFor(shared.NewID().String()) {
		t.Fatal("the session must NOT count as an SSO sign-in of any other organization")
	}
}

type recordingSessionRepo struct {
	sessiondom.Repository
	created []*sessiondom.Session
}

func (r *recordingSessionRepo) Create(_ context.Context, s *sessiondom.Session) error {
	r.created = append(r.created, s)
	return nil
}

// Social OAuth (GitHub/Google/personal Microsoft) is federated but issued by
// no organization: it is exempt from no organization's policies.
func TestOAuthSession_NoIssuingTenant(t *testing.T) {
	repo := &recordingSessionRepo{}
	s := NewOAuthService(nil, repo, cbRefreshRepo{}, config.OAuthConfig{}, config.AuthConfig{
		JWTSecret: "oauth-issuer-test-secret-0123456789abcdef", JWTIssuer: "t",
		AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
	}, logger.NewNop())
	u, err := userdom.New("social@example.com", "Social")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := s.createSession(context.Background(), u); err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if len(repo.created) != 1 {
		t.Fatalf("created %d sessions, want 1", len(repo.created))
	}
	sess := repo.created[0]
	if !sess.AuthMethod().IsFederated() {
		t.Fatalf("social OAuth session should still be stamped federated, got %q", sess.AuthMethod())
	}
	if !sess.IDPTenantID().IsZero() {
		t.Fatalf("social OAuth must record no issuing tenant, got %s", sess.IDPTenantID())
	}
	if sess.FederatedFor(shared.NewID().String()) {
		t.Fatal("social OAuth must not count as an SSO sign-in of any organization")
	}
	if got := sess.AuthMethodFor(shared.NewID().String()); got != sessiondom.AuthMethodPassword {
		t.Fatalf("AuthMethodFor any tenant = %q, want password", got)
	}
}
