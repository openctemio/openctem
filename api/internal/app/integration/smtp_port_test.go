package integration

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An organization's SMTP relay is used on a mail port only: create and
// update refuse any other port, so the platform's SMTP client cannot be
// pointed at a service that is not a mail relay.
func TestEmailCredentials_RefuseNonMailPort(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	withPort := func(port string) string {
		return strings.Replace(smtpCredsJSON, `"smtp_port":587`, `"smtp_port":`+port, 1) + `}`
	}

	intg := newEmailIntegration()
	for _, port := range []string{"6379", "22", "80", "443", "5432", "8080", "1025"} {
		if err := s.setEmailCredentials(intg, withPort(port)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("create on port %s: err = %v, want a validation error", port, err)
		}
	}
	for _, port := range []string{"25", "465", "587", "2525"} {
		if err := s.setEmailCredentials(intg, withPort(port)); err != nil {
			t.Errorf("create on port %s: %v", port, err)
		}
	}
	if err := s.updateEmailCredentials(intg, withPort("6379")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("update to port 6379: err = %v, want a validation error", err)
	}
	if got := intg.Metadata()["smtp_port"]; got != 2525 {
		t.Errorf("a refused update changed the stored port to %v", got)
	}
}
