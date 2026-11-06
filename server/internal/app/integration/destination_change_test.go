package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A stored secret must never follow a changed destination: the update has to
// carry new credentials (which replace the stored ones) or it is refused, so
// the delivery that follows an update cannot present the old secret to a new
// host.

func emailWithStoredSecret(t *testing.T, s *IntegrationService) *integrationdom.Integration {
	t.Helper()
	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`, false); err != nil {
		t.Fatal(err)
	}
	return intg
}

func TestEmailUpdate_DestinationChangeNeedsNewCredentials(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	tail := `"to_emails":["soc@example.com"]}`
	cases := map[string]string{
		"host":         `{"smtp_host":"mx.other.example","smtp_port":587,"use_starttls":true,` + tail,
		"host case":    `{"smtp_host":"MX.OTHER.example","smtp_port":587,"use_starttls":true,` + tail,
		"port":         `{"smtp_host":"smtp.example.com","smtp_port":25,"use_starttls":true,` + tail,
		"tls weakened": `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":false,` + tail,
		"tls omitted":  `{"smtp_host":"smtp.example.com","smtp_port":587,` + tail,
	}
	for name, upd := range cases {
		t.Run(name, func(t *testing.T) {
			intg := emailWithStoredSecret(t, s)
			before := intg.CredentialsEncrypted()
			if err := s.updateEmailCredentials(intg, upd, false); !errors.Is(err, ErrCredentialsRequiredForNewHost) {
				t.Fatalf("err = %v, want ErrCredentialsRequiredForNewHost", err)
			}
			if intg.CredentialsEncrypted() != before {
				t.Fatal("stored credentials changed by a refused update")
			}
		})
	}
}

func TestEmailUpdate_NewHostWithNewCredentialsReplacesStoredSecret(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	intg := emailWithStoredSecret(t, s)
	upd := `{"smtp_host":"mx.other.example","smtp_port":587,"use_starttls":true,"username":"u2","password":"p2","to_emails":["soc@example.com"]}`
	if err := s.updateEmailCredentials(intg, upd, false); err != nil {
		t.Fatalf("update refused: %v", err)
	}
	cfg, err := s.buildNotificationConfig(intg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Email.SMTPHost != "mx.other.example" || cfg.Email.Password != "p2" {
		t.Fatalf("host %q password %q: want the new host with the new password", cfg.Email.SMTPHost, cfg.Email.Password)
	}
}

func TestEmailUpdate_SameDestinationKeepsStoredSecret(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	intg := emailWithStoredSecret(t, s)
	upd := `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,"to_emails":["ops@example.com"]}`
	if err := s.updateEmailCredentials(intg, upd, false); err != nil {
		t.Fatalf("update refused: %v", err)
	}
	cfg, err := s.buildNotificationConfig(intg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Email.Password != "p" {
		t.Fatalf("password %q, want the stored one kept", cfg.Email.Password)
	}
}

// Rows written before the relay moved into metadata keep it inside the
// encrypted credentials; a host change on such a row is detected too.
func TestEmailUpdate_LegacyRowDestinationChangeNeedsNewCredentials(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	intg := newEmailIntegration()
	intg.SetCredentials(smtpCredsJSON + `}`)
	upd := `{"smtp_host":"mx.other.example","smtp_port":587,"use_starttls":true,"to_emails":["soc@example.com"]}`
	if err := s.updateEmailCredentials(intg, upd, false); !errors.Is(err, ErrCredentialsRequiredForNewHost) {
		t.Fatalf("err = %v, want ErrCredentialsRequiredForNewHost", err)
	}
}

func splunkWithToken() *integrationdom.Integration {
	intg := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "siem",
		integrationdom.CategoryNotification, integrationdom.ProviderSplunk, integrationdom.AuthTypeToken)
	intg.SetCredentials("hec-secret")
	intg.SetMetadata(map[string]any{"hec_url": "https://splunk.corp.example:8088"})
	return intg
}

// updateRepo serves one integration and records whether an update was saved.
type updateRepo struct {
	integrationdom.Repository
	intg    *integrationdom.Integration
	updated bool
}

func (r *updateRepo) GetByID(context.Context, shared.ID) (*integrationdom.Integration, error) {
	return r.intg, nil
}

func (r *updateRepo) Update(context.Context, *integrationdom.Integration) error {
	r.updated = true
	return nil
}

func TestSplunkUpdate_HecHostChangeNeedsNewToken(t *testing.T) {
	intg := splunkWithToken()
	repo := &updateRepo{intg: intg}
	svc := NewIntegrationService(repo, nil, nil, logger.NewNop())

	_, err := svc.UpdateNotificationIntegration(context.Background(), intg.ID().String(), intg.TenantID().String(),
		UpdateNotificationIntegrationInput{Metadata: map[string]any{"hec_url": "https://collector.other.example"}})
	if !errors.Is(err, ErrCredentialsRequiredForNewHost) {
		t.Fatalf("err = %v, want ErrCredentialsRequiredForNewHost", err)
	}
	if repo.updated {
		t.Fatal("a refused update was saved")
	}
	if intg.CredentialsEncrypted() != "hec-secret" {
		t.Fatal("stored token changed")
	}
}

func TestRequireCredentialsForDestinationChange(t *testing.T) {
	stored := splunkWithToken()
	empty := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "siem",
		integrationdom.CategoryNotification, integrationdom.ProviderSplunk, integrationdom.AuthTypeToken)
	for name, tc := range map[string]struct {
		intg           *integrationdom.Integration
		changed, given bool
		wantErr        bool
	}{
		"moved, no new secret":      {stored, true, false, true},
		"moved, new secret":         {stored, true, true, false},
		"same destination":          {stored, false, false, false},
		"moved, nothing stored yet": {empty, true, false, false},
	} {
		err := requireCredentialsForDestinationChange(tc.intg, tc.changed, tc.given)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", name, err, tc.wantErr)
		}
	}
}
