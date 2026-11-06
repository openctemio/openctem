package unit

import (
	"context"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fedLoginAuditRepo struct {
	mockAuthAuditRepo
	logs []*audit.AuditLog
}

func (r *fedLoginAuditRepo) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

// A federated sign-in (here the SAML tail) is audited as auth.login with its
// method, and its session records the browser's address and user agent. It
// used to write no audit event at all and store an empty device, so SSO
// sign-ins (the main path for enterprise organizations) were invisible in
// the audit log and showed a blank device under My account → Sessions.
func TestCompleteFederatedLogin_AuditedWithClientInfo(t *testing.T) {
	sessions := newSSOmockSessionRepo()
	svc := newTestSSOService(newSSOmockIPRepo(), newSSOmockTenantRepo(), newSSOmockUserRepo(),
		sessions, newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())
	svc.SetDomainVerifier(ssoUnitVerifier{"example.com": true})
	rec := &fedLoginAuditRepo{}
	svc.SetAuditService(auditsvc.NewAuditService(rec, logger.NewNop()))
	tn := createTestTenant("saml-audit-org")

	ctx := auth.WithClientInfo(context.Background(), "198.51.100.7", "Mozilla/5.0 test")
	if _, err := svc.CompleteFederatedLogin(ctx, tn, "saml@example.com", "Saml", "member", true); err != nil {
		t.Fatalf("CompleteFederatedLogin: %v", err)
	}

	for _, s := range sessions.sessions {
		if s.IPAddress() != "198.51.100.7" || s.UserAgent() != "Mozilla/5.0 test" {
			t.Fatalf("session device = %q / %q, want the browser's", s.IPAddress(), s.UserAgent())
		}
	}
	var logins []*audit.AuditLog
	for _, l := range rec.logs {
		if l.Action() == audit.ActionAuthLogin {
			logins = append(logins, l)
		}
	}
	if len(logins) != 1 {
		t.Fatalf("expected one auth.login event, got %d", len(logins))
	}
	if tid := logins[0].TenantID(); tid == nil || !tid.Equals(tn.ID()) {
		t.Fatalf("the event must belong to the issuing organization %s, got %v", tn.ID(), tid)
	}
	if logins[0].ActorIP() != "198.51.100.7" || logins[0].Metadata()["method"] != "saml" {
		t.Fatalf("event must carry the IP and method=saml, got ip=%q meta=%v", logins[0].ActorIP(), logins[0].Metadata())
	}
}
