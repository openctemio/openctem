package integration

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const smtpCredsJSON = `{"smtp_host":"smtp.example.com","smtp_port":587,"username":"u","password":"p",` +
	`"from_email":"alerts@example.com","to_emails":["soc@example.com"],"use_starttls":true`

func newEmailIntegration() *integrationdom.Integration {
	return integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "mail",
		integrationdom.CategoryNotification, integrationdom.ProviderEmail, integrationdom.AuthTypeBasic)
}

// A tenant may not turn off certificate verification for the relay it sends
// its SMTP password to (RFC-049 F-5): create and update refuse skip_verify,
// and nothing about it is stored.
func TestEmailCredentials_RefuseSkipVerify(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}

	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`,"skip_verify":true}`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("create with skip_verify: err = %v, want a validation error", err)
	}
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`,"skip_verify":false}`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := intg.Metadata()["skip_verify"]; ok {
		t.Fatal("skip_verify stored in metadata")
	}
	if err := s.updateEmailCredentials(intg, smtpCredsJSON+`,"skip_verify":true}`); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("update with skip_verify: err = %v, want a validation error", err)
	}
	if err := s.updateEmailCredentials(intg, smtpCredsJSON+`}`); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, ok := intg.Metadata()["skip_verify"]; ok {
		t.Fatal("skip_verify stored in metadata after update")
	}
}

// An integration stored before the flag was removed still has skip_verify in
// its metadata (or in legacy all-in-one credentials); it is read without it,
// so delivery verifies the relay certificate.
func TestEmailConfig_IgnoresStoredSkipVerify(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}

	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`); err != nil {
		t.Fatal(err)
	}
	meta := intg.Metadata()
	meta["skip_verify"] = true
	intg.SetMetadata(meta)
	if _, err := s.buildEmailConfig(intg, `{"username":"u","password":"p"}`); err != nil {
		t.Fatalf("stored metadata: %v", err)
	}
	if _, err := s.parseEmailCredentials(smtpCredsJSON + `,"skip_verify":true}`); err != nil {
		t.Fatalf("legacy credentials: %v", err)
	}
	// notifier.EmailConfig has no field to carry the flag: the client always
	// verifies (TLSConfig(host, false)), which the compiler enforces.
}
