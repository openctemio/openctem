package auth

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recSender struct {
	mu    sync.Mutex
	sends int
}

func (r *recSender) IsConfigured() bool { return true }
func (r *recSender) Send(context.Context, *emaildom.Message) error {
	r.mu.Lock()
	r.sends++
	r.mu.Unlock()
	return nil
}
func (r *recSender) SendTemplate(context.Context, string, emaildom.Template, any) error {
	r.mu.Lock()
	r.sends++
	r.mu.Unlock()
	return nil
}
func (r *recSender) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.sends }

// relayStub answers the organization relay lookup: a config, an "unusable"
// error, or nothing; it counts the lookups.
type relayStub struct {
	mu    sync.Mutex
	calls int
	cfg   *emaildom.Config
	err   error
}

func (r *relayStub) GetTenantSMTPConfig(context.Context, string) (*emaildom.Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.cfg, r.err
}
func (r *relayStub) lookups() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func newRelayTestService(platform *recSender, relay *relayStub) *EmailService {
	s := NewEmailService(platform, config.SMTPConfig{BaseURL: "https://app.example.com"}, "App", logger.NewNop())
	s.SetTenantSMTPResolver(relay)
	return s
}

// Account security mail goes through the platform relay only, whatever the
// organization relay says: no lookup, no send through an organization relay.
func TestAccountSecurityMail_NeverUsesOrganizationRelay(t *testing.T) {
	platform := &recSender{}
	relay := &relayStub{cfg: &emaildom.Config{Host: "smtp.org.example", Port: 587, From: "a@org.example"}}
	s := newRelayTestService(platform, relay)
	ctx := context.Background()

	if err := s.SendVerificationEmail(ctx, "u@example.com", "U", "tok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.SendPasswordResetEmail(ctx, "u@example.com", "U", "tok", time.Hour, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SendPasswordChangedEmail(ctx, "u@example.com", "U", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SendWelcomeEmail(ctx, "u@example.com", "U"); err != nil {
		t.Fatal(err)
	}
	if err := s.SendDomainManagedEmail(ctx, "u@example.com", "example.com"); err != nil {
		t.Fatal(err)
	}
	s.NotifyMFADisabled(ctx, "u@example.com", "U", "192.0.2.1")
	s.NotifyRecoveryCodeUsed(ctx, "u@example.com", "U", "192.0.2.1", 3)
	s.NotifyPasswordChanged(ctx, "u@example.com", "U", "192.0.2.1")
	s.NotifySSOChangePending(ctx, "o@example.com", "O", "Org", "summary")
	s.NotifySAMLCertificateExpiry(ctx, "o@example.com", "O", "subject", "message")
	s.NotifySupportAccess(ctx, "o@example.com", "O", "subject", "message")
	s.NotifyOwnershipTransfer(ctx, "o@example.com", "O", "subject", "message")
	s.NotifyEmailRelayStopped(ctx, "o@example.com", "O", "subject", "message")

	deadline := time.Now().Add(3 * time.Second)
	for platform.count() < 13 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := platform.count(); got != 13 {
		t.Fatalf("platform relay carried %d of 13 account mails", got)
	}
	if relay.lookups() != 0 {
		t.Fatalf("account security mail consulted the organization relay %d times", relay.lookups())
	}
	if s.HasTenantSMTP(ctx, "11111111-1111-4111-8111-111111111111") {
		t.Fatal("an organization relay must not make account verification possible")
	}
}

// A set-password link (account setup, first owner, owner recovery) goes
// through the platform relay only: an active organization relay is never
// looked up, never used, and does not decide whether the link can be mailed.
func TestAccountSetupLink_NeverUsesOrganizationRelay(t *testing.T) {
	ctx := context.Background()
	tenant := "11111111-1111-4111-8111-111111111111"
	platform := &recSender{}
	relay := &relayStub{cfg: &emaildom.Config{Host: "smtp.org.example", Port: 587, From: "a@org.example"}}
	s := newRelayTestService(platform, relay)

	if !s.CanDeliverTo(ctx, tenant) {
		t.Fatal("the platform relay is configured: the link can be mailed")
	}
	if err := s.SendAccountSetupEmail(ctx, tenant, "owner@example.com", "Owner", "Org", "tok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if platform.count() != 1 || relay.lookups() != 0 {
		t.Fatalf("setup link: platform sends = %d, organization relay lookups = %d (want 1, 0)", platform.count(), relay.lookups())
	}

	// An organization relay that is broken, or the only one configured, changes nothing.
	relay.err = errors.New("relay unusable")
	if err := s.SendAccountSetupEmail(ctx, tenant, "owner@example.com", "Owner", "Org", "tok", time.Hour); err != nil || platform.count() != 2 {
		t.Fatalf("a broken organization relay must not affect the setup link: %v, sends = %d", err, platform.count())
	}

	// No platform relay: the link is not mailed through the organization relay either.
	orgOnly := &recSender{}
	noPlatform := NewEmailService(nil, config.SMTPConfig{BaseURL: "https://app.example.com"}, "App", logger.NewNop())
	noPlatform.SetTenantSMTPResolver(&relayStub{cfg: &emaildom.Config{Host: "smtp.org.example", Port: 587, From: "a@org.example"}})
	if noPlatform.CanDeliverTo(ctx, tenant) {
		t.Fatal("an organization relay must not make a setup link deliverable")
	}
	if err := noPlatform.SendAccountSetupEmail(ctx, tenant, "owner@example.com", "Owner", "Org", "tok", time.Hour); err == nil {
		t.Fatal("no platform relay: the setup link must not be sent")
	}
	if orgOnly.count() != 0 {
		t.Fatal("unreachable")
	}
}

// Every Send* and Notify* method of the service is classified here: a new
// one fails this test until its class is chosen on purpose (account mail
// must not take an organization relay).
func TestEmailService_EveryMailMethodIsClassified(t *testing.T) {
	accountSecurity := []string{
		"NotifyEmailRelayStopped", "NotifyMFADisabled", "NotifyOwnershipTransfer", "NotifyPasswordChanged",
		"NotifyRecoveryCodeUsed", "NotifySAMLCertificateExpiry", "NotifySSOChangePending", "NotifySupportAccess",
		"SendDomainManagedEmail", "SendPasswordChangedEmail", "SendPasswordResetEmail", "SendVerificationEmail",
		"SendWelcomeEmail",
		// A set-password link is a credential: platform relay only.
		"SendAccountSetupEmail",
	}
	organizationMail := []string{
		"SendMemberReactivatedEmail", "SendMemberSuspendedEmail", "SendReport",
		"SendTeamInvitationEmail",
	}
	var got []string
	typ := reflect.TypeOf(&EmailService{})
	for i := 0; i < typ.NumMethod(); i++ {
		n := typ.Method(i).Name
		if strings.HasPrefix(n, "Send") || strings.HasPrefix(n, "Notify") {
			got = append(got, n)
		}
	}
	want := append(append([]string{}, accountSecurity...), organizationMail...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mail methods changed; classify the new ones.\n got  %v\n want %v", got, want)
	}
}

// Organization transactional mail falls back to the platform relay when the
// organization's relay cannot be used; reports never do.
func TestOrganizationMail_FallbackRules(t *testing.T) {
	ctx := context.Background()
	tenant := "11111111-1111-4111-8111-111111111111"

	platform := &recSender{}
	relay := &relayStub{err: errors.Join(emaildom.ErrTenantRelayUnusable, errors.New("sender domain not verified"))}
	s := newRelayTestService(platform, relay)

	if err := s.SendTeamInvitationEmail(ctx, "n@example.com", "Inviter", "Team", "tok", time.Hour, tenant); err != nil {
		t.Fatal(err)
	}
	if platform.count() != 1 {
		t.Fatalf("an invitation must fall back to the platform relay, sends = %d", platform.count())
	}
	if err := s.SendReport(ctx, tenant, []string{"r@example.com"}, "Weekly", "<p>x</p>"); !errors.Is(err, emaildom.ErrTenantRelayUnusable) {
		t.Fatalf("report err = %v, want ErrTenantRelayUnusable", err)
	}
	if platform.count() != 1 {
		t.Fatal("a report was sent through the platform relay although the organization chose its own")
	}

	// No organization relay (mode off or none ticked): the platform relay is
	// the configured sender for both.
	relay.err, relay.cfg = nil, nil
	if err := s.SendReport(ctx, tenant, []string{"r@example.com"}, "Weekly", "<p>x</p>"); err != nil {
		t.Fatal(err)
	}
	if platform.count() != 2 {
		t.Fatalf("report without an organization relay must use the platform relay, sends = %d", platform.count())
	}
	// Platform-level mail (no organization) never looks up a relay.
	before := relay.lookups()
	if err := s.SendReport(ctx, "", []string{"a@example.com"}, "Alert", "<p>x</p>"); err != nil {
		t.Fatal(err)
	}
	if relay.lookups() != before {
		t.Fatal("platform mail looked up an organization relay")
	}
}
