package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	emailpkg "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func managedRelay(t *testing.T) {
	t.Helper()
	emailpkg.SetManagedTenantRelay(true)
	t.Cleanup(func() { emailpkg.SetManagedTenantRelay(false) })
}

// On a managed service an organization relay is saved only on a submission
// port with AUTH and TLS; a self-managed install keeps its relays.
func TestEmailCredentials_ManagedServiceRules(t *testing.T) {
	managedRelay(t)
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	tail := `"from_email":"a@example.com","to_emails":["soc@example.com"]`
	bad := map[string]string{
		"port 25":  `{"smtp_host":"smtp.example.com","smtp_port":25,"username":"u","password":"p","use_starttls":true,` + tail + `}`,
		"no auth":  `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,` + tail + `}`,
		"no tls":   `{"smtp_host":"smtp.example.com","smtp_port":587,"username":"u","password":"p",` + tail + `}`,
		"no creds": `{"smtp_host":"smtp.example.com","smtp_port":25,` + tail + `}`,
	}
	for name, creds := range bad {
		err := s.setEmailCredentials(newEmailIntegration(), creds)
		if !errors.Is(err, shared.ErrValidation) || !errors.Is(err, emailpkg.ErrTenantRelayPolicy) {
			t.Errorf("create %s: err = %v, want a validation error from the relay policy", name, err)
		}
	}
	if err := s.setEmailCredentials(newEmailIntegration(), smtpCredsJSON+`}`); err != nil {
		t.Fatalf("a compliant relay was refused: %v", err)
	}

	// An update that keeps the stored login is judged with it; one that
	// drops TLS is refused.
	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`); err != nil {
		t.Fatal(err)
	}
	keep := `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,"to_emails":["ops@example.com"]}`
	if err := s.updateEmailCredentials(intg, keep); err != nil {
		t.Fatalf("update that keeps the stored login refused: %v", err)
	}
	weak := `{"smtp_host":"smtp.example.com","smtp_port":587,"username":"u","password":"p","use_starttls":false,"use_tls":false,"to_emails":["ops@example.com"]}`
	if err := s.updateEmailCredentials(intg, weak); !errors.Is(err, emailpkg.ErrTenantRelayNeedsTLS) {
		t.Fatalf("update without TLS: err = %v, want ErrTenantRelayNeedsTLS", err)
	}
}

func TestClassifyConnFailure_RelayPolicy(t *testing.T) {
	f := ClassifyConnFailure(errors.Join(errors.New("create client"), emailpkg.ErrTenantRelayPort25))
	if f.Code != apierror.CodeIntegrationEmailRelayPolicy {
		t.Fatalf("code = %q", f.Code)
	}
}

// --- stop-and-notify ---

type relayRepo struct {
	integrationdom.Repository
	intg    *integrationdom.Integration
	updates int
}

func (r *relayRepo) GetByID(context.Context, shared.ID) (*integrationdom.Integration, error) {
	return r.intg, nil
}
func (r *relayRepo) Update(context.Context, *integrationdom.Integration) error {
	r.updates++
	return nil
}

type relayOwnersStub struct{ owner ssochange.OwnerContact }

func (o relayOwnersStub) ListActiveOwners(context.Context, shared.ID) ([]ssochange.OwnerContact, error) {
	return []ssochange.OwnerContact{o.owner}, nil
}

type relayInApp struct {
	got []notificationdom.NotificationParams
}

func (n *relayInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.got = append(n.got, p)
	return nil
}

type relayMail struct{ to []string }

func (m *relayMail) NotifyEmailRelayStopped(_ context.Context, to, _, _, _ string) {
	m.to = append(m.to, to)
}

// A relay the rules refuse stops the channel with the policy status and tells
// each owner once, in-app and by mail; a repeat refusal and another
// organization's id change nothing.
func TestEmailRelayRefused_StopsChannelAndNotifiesOwnersOnce(t *testing.T) {
	intg := newEmailIntegration()
	intg.SetConnected()
	repo := &relayRepo{intg: intg}
	s := &IntegrationService{repo: repo, logger: logger.NewDefault()}
	inApp, mail := &relayInApp{}, &relayMail{}
	s.relayOwners = relayOwnersStub{ssochange.OwnerContact{UserID: shared.NewID(), Email: "owner@example.com", Name: "O"}}
	s.relayInApp, s.relayMailer = inApp, mail

	// Another organization's id: nothing happens.
	s.EmailRelayRefused(context.Background(), shared.NewID(), intg.ID(), emailpkg.ErrTenantRelayNeedsAuth)
	if repo.updates != 0 || len(inApp.got) != 0 {
		t.Fatal("a foreign tenant id changed the integration")
	}

	s.EmailRelayRefused(context.Background(), intg.TenantID(), intg.ID(), emailpkg.ErrTenantRelayNeedsAuth)
	if intg.Status() != integrationdom.StatusError || intg.StatusCode() != string(apierror.CodeIntegrationEmailRelayPolicy) {
		t.Fatalf("status %s code %q, want error with the relay policy code", intg.Status(), intg.StatusCode())
	}
	if len(inApp.got) != 1 || len(mail.to) != 1 || mail.to[0] != "owner@example.com" {
		t.Fatalf("notices: in-app %d, mail %v, want one each", len(inApp.got), mail.to)
	}
	if strings.Contains(inApp.got[0].Body, "—") {
		t.Fatal("notice text must not contain an em dash")
	}

	s.EmailRelayRefused(context.Background(), intg.TenantID(), intg.ID(), emailpkg.ErrTenantRelayNeedsAuth)
	if repo.updates != 1 || len(inApp.got) != 1 || len(mail.to) != 1 {
		t.Fatalf("a repeat refusal acted again: updates %d, in-app %d, mail %d", repo.updates, len(inApp.got), len(mail.to))
	}
}
