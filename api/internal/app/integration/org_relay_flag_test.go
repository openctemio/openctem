package integration

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
)

// A new integration carries the flag on, an update keeps it, and an explicit
// value wins.
func TestEmailCredentials_OrgMailFlag(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	intg := newEmailIntegration()
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`); err != nil {
		t.Fatal(err)
	}
	if on, _ := intg.Metadata()[integrationdom.MetaEmailOrgMail].(bool); !on {
		t.Fatal("a new integration must have org_mail on")
	}
	upd := `{"smtp_host":"smtp.example.com","smtp_port":587,"use_starttls":true,"to_emails":["ops@example.com"]`
	if err := s.updateEmailCredentials(intg, upd+`,"org_mail":false}`); err != nil {
		t.Fatal(err)
	}
	if on, _ := intg.Metadata()[integrationdom.MetaEmailOrgMail].(bool); on {
		t.Fatal("an explicit false must switch it off")
	}
	if err := s.updateEmailCredentials(intg, upd+`}`); err != nil {
		t.Fatal(err)
	}
	if on, _ := intg.Metadata()[integrationdom.MetaEmailOrgMail].(bool); on {
		t.Fatal("an update without the field must keep the stored value")
	}
}
