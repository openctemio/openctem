package integration

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func orgMailOn(intg *integrationdom.Integration) bool {
	on, _ := intg.Metadata()[integrationdom.MetaEmailOrgMail].(bool)
	return on
}

// A new channel does not send organization mail through its relay unless the
// request says so, an update keeps the stored value, and an explicit false
// always works.
func TestEmailCredentials_OrgMailFlag(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`, true); err != nil {
		t.Fatal(err)
	}
	if orgMailOn(intg) {
		t.Fatal("a new integration must have org_mail off")
	}
	upd := `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,"to_emails":["ops@example.com"]`
	if err := s.updateEmailCredentials(intg, upd+`,"org_mail":true}`, true); err != nil {
		t.Fatal(err)
	}
	if !orgMailOn(intg) {
		t.Fatal("an administrator's explicit true must switch it on")
	}
	if err := s.updateEmailCredentials(intg, upd+`}`, false); err != nil {
		t.Fatal(err)
	}
	if !orgMailOn(intg) {
		t.Fatal("an update without the field must keep the stored value")
	}
	if err := s.updateEmailCredentials(intg, upd+`,"org_mail":false}`, false); err != nil {
		t.Fatal(err)
	}
	if orgMailOn(intg) {
		t.Fatal("an explicit false must switch it off, for any caller")
	}
}

// A caller who may manage integrations but is not an owner or administrator
// cannot turn organization mail on, on create or on update, and nothing is
// stored when refused.
func TestEmailCredentials_OrgMailNeedsOwnerOrAdmin(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}

	intg := newEmailIntegration()
	err := s.setEmailCredentials(intg, smtpCredsJSON+`,"org_mail":true}`, false)
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("create with org_mail by a non-admin = %v, want ErrForbidden", err)
	}
	if orgMailOn(intg) {
		t.Fatal("a refused create stored org_mail on")
	}
	// The same request by an administrator works.
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`,"org_mail":true}`, true); err != nil || !orgMailOn(intg) {
		t.Fatalf("create with org_mail by an administrator: %v on=%v", err, orgMailOn(intg))
	}

	off := newEmailIntegration()
	if err := s.setEmailCredentials(off, smtpCredsJSON+`}`, false); err != nil {
		t.Fatal(err)
	}
	upd := `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,"to_emails":["ops@example.com"],"org_mail":true}`
	if err := s.updateEmailCredentials(off, upd, false); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("update turning org_mail on by a non-admin = %v, want ErrForbidden", err)
	}
	if orgMailOn(off) {
		t.Fatal("a refused update turned org_mail on")
	}
	// Keeping it on (already on) is not "turning it on".
	if err := s.updateEmailCredentials(intg, upd, false); err != nil || !orgMailOn(intg) {
		t.Fatalf("a non-admin re-saving an already-on flag: %v", err)
	}
}
