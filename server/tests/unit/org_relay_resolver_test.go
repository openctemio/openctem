package unit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	emailpkg "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type relayModeStub emailpkg.RelayMode

func (m relayModeStub) RelayMode(context.Context) emailpkg.RelayMode { return emailpkg.RelayMode(m) }

type domainBook map[string]*verifieddomain.VerifiedDomain // "tenant|domain"

func (b domainBook) GetByTenantAndDomain(_ context.Context, t shared.ID, d string) (*verifieddomain.VerifiedDomain, error) {
	if v, ok := b[t.String()+"|"+d]; ok {
		return v, nil
	}
	return nil, verifieddomain.ErrNotFound
}

func verified(t *testing.T, tenant shared.ID, domain string) *verifieddomain.VerifiedDomain {
	t.Helper()
	d, err := verifieddomain.New(shared.NewID(), tenant, domain, "tok")
	if err != nil {
		t.Fatal(err)
	}
	d.MarkVerified(time.Now())
	return d
}

// The resolver reads what the integration service really stores (connection
// settings in the metadata, the login in the encrypted credentials), applies
// the platform mode, the transport rule and the sender-domain rule, and never
// hands one organization's relay to another.
func TestOrgRelayResolver_ReadsStoredShape(t *testing.T) {
	enc := crypto.NewNoOpEncryptor()
	repo := newMockIntegrationRepo()
	svc := integrationapp.NewIntegrationService(repo, newMockSCMExtRepo(), enc, logger.NewNop())
	svc.SetNotificationExtensionRepository(newMockNotificationExtRepo())
	ctx := context.Background()
	tenant := shared.NewID()
	seq := 0
	creds := `{"smtp_host":"smtp.org.example","smtp_port":587,"username":"mailer","password":"s3cret","from_email":"it@org.example",` +
		`"to_emails":["soc@org.example"],"use_starttls":true`

	// mk stores an e-mail integration through the service (the real stored
	// shape) and marks it connected.
	mk := func(t *testing.T, tail string) *integrationdom.Integration {
		t.Helper()
		seq++
		if !strings.Contains(tail, "org_mail") {
			// A new channel has organization mail off; these cases need it on.
			tail += `,"org_mail":true`
		}
		res, err := svc.CreateNotificationIntegration(ctx, integrationapp.CreateNotificationIntegrationInput{
			TenantID: tenant.String(), Name: fmt.Sprintf("mail-%d", seq), Provider: "email", AuthType: "basic",
			Credentials: creds + tail + `}`, CanEnableOrgMail: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		intg := res.Integration
		intg.SetConnected()
		return intg
	}
	resolver := func(intg *integrationdom.Integration, mode emailpkg.RelayMode, book domainBook) *auth.IntegrationSMTPResolver {
		only := newMockIntegrationRepo()
		only.integrations[intg.ID()] = intg
		return auth.NewIntegrationSMTPResolver(only, enc.DecryptString, relayModeStub(mode), book, logger.NewNop())
	}

	t.Run("mode on uses the stored relay and login", func(t *testing.T) {
		intg := mk(t, "")
		cfg, err := resolver(intg, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, intg.TenantID().String())
		if err != nil || cfg == nil {
			t.Fatalf("cfg %v err %v", cfg, err)
		}
		if cfg.Host != "smtp.org.example" || cfg.Port != 587 || cfg.User != "mailer" || cfg.Password != "s3cret" ||
			cfg.From != "it@org.example" || !cfg.TLS || cfg.SkipVerify {
			t.Fatalf("cfg = %+v", cfg)
		}
	})

	t.Run("mode off and an integration saved before the flag use the platform relay", func(t *testing.T) {
		intg := mk(t, "")
		if cfg, err := resolver(intg, emailpkg.RelayModeOff, nil).GetTenantSMTPConfig(ctx, intg.TenantID().String()); cfg != nil || err != nil {
			t.Fatalf("mode off: cfg %v err %v", cfg, err)
		}
		legacy := mk(t, `,"org_mail":false`)
		if cfg, err := resolver(legacy, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, legacy.TenantID().String()); cfg != nil || err != nil {
			t.Fatalf("org_mail off: cfg %v err %v", cfg, err)
		}
		meta := legacy.Metadata()
		delete(meta, integrationdom.MetaEmailOrgMail)
		legacy.SetMetadata(meta)
		if cfg, err := resolver(legacy, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, legacy.TenantID().String()); cfg != nil || err != nil {
			t.Fatalf("flag absent: cfg %v err %v", cfg, err)
		}
	})

	t.Run("another organization never gets the relay", func(t *testing.T) {
		intg := mk(t, "")
		if cfg, err := resolver(intg, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, shared.NewID().String()); cfg != nil || err != nil {
			// The repo double returns the item for any tenant; the resolver
			// must still compare the integration's own tenant.
			t.Fatalf("foreign tenant: cfg %v err %v", cfg, err)
		}
	})

	t.Run("verified sender needs a verified domain of the same organization", func(t *testing.T) {
		intg := mk(t, "")
		tenant := intg.TenantID()
		_, err := resolver(intg, emailpkg.RelayModeVerifiedSender, domainBook{}).GetTenantSMTPConfig(ctx, tenant.String())
		if !errors.Is(err, emailpkg.ErrTenantRelayUnusable) {
			t.Fatalf("unverified sender domain: err = %v", err)
		}
		other := domainBook{shared.NewID().String() + "|org.example": nil}
		for k := range other {
			other[k] = verified(t, shared.NewID(), "org.example")
		}
		if _, err := resolver(intg, emailpkg.RelayModeVerifiedSender, other).GetTenantSMTPConfig(ctx, tenant.String()); !errors.Is(err, emailpkg.ErrTenantRelayUnusable) {
			t.Fatalf("another organization's verified domain was accepted: %v", err)
		}
		own := domainBook{tenant.String() + "|org.example": verified(t, tenant, "org.example")}
		if cfg, err := resolver(intg, emailpkg.RelayModeVerifiedSender, own).GetTenantSMTPConfig(ctx, tenant.String()); err != nil || cfg == nil {
			t.Fatalf("verified own domain: cfg %v err %v", cfg, err)
		}
		pending, _ := verifieddomain.New(shared.NewID(), tenant, "org.example", "tok")
		if _, err := resolver(intg, emailpkg.RelayModeVerifiedSender, domainBook{tenant.String() + "|org.example": pending}).GetTenantSMTPConfig(ctx, tenant.String()); !errors.Is(err, emailpkg.ErrTenantRelayUnusable) {
			t.Fatalf("a pending domain was accepted: %v", err)
		}
	})

	t.Run("managed rules and connection state", func(t *testing.T) {
		emailpkg.SetManagedTenantRelay(true)
		t.Cleanup(func() { emailpkg.SetManagedTenantRelay(false) })
		intg := mk(t, "")
		meta := intg.Metadata()
		meta["smtp_port"] = 25
		intg.SetMetadata(meta)
		if _, err := resolver(intg, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, intg.TenantID().String()); !errors.Is(err, emailpkg.ErrTenantRelayUnusable) {
			t.Fatalf("port 25 on a managed service: err = %v", err)
		}
		emailpkg.SetManagedTenantRelay(false)
		failed := mk(t, "")
		failed.SetFailure("X", "down")
		if _, err := resolver(failed, emailpkg.RelayModeOn, nil).GetTenantSMTPConfig(ctx, failed.TenantID().String()); !errors.Is(err, emailpkg.ErrTenantRelayUnusable) {
			t.Fatalf("a failed integration: err = %v", err)
		}
	})
}
