package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	notifier "github.com/openctemio/openctem/server/internal/infra/notifier"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/server/pkg/domain/integration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// E-mail credentials that are not the JSON object of the relay settings (a
// bare address, a URL) are a validation error that names the expected
// shape, never an internal error, on create and on update. The decoder's
// own text is not part of the message.
func TestEmailCredentials_NotJSONIsValidation(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor()}
	for _, creds := range []string{"security-alerts@example.com", "https://example.com", `["a"]`, `{"smtp_host":`} {
		for name, set := range map[string]func() error{
			"create": func() error { return s.setEmailCredentials(newEmailIntegration(), creds, false) },
			"update": func() error { return s.updateEmailCredentials(newEmailIntegration(), creds, false) },
		} {
			err := set()
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s %q: err = %v, want a validation error", name, creds, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "smtp_host") || strings.Contains(msg, "invalid character") || strings.Contains(msg, "json:") {
				t.Errorf("%s %q: message %q must name the expected fields and carry no decoder text", name, creds, msg)
			}
		}
	}
}

// hangingClient is a notification client whose test never answers until its
// context ends, as a relay that accepts the connection and then says nothing.
type hangingClient struct{ notifier.Client }

func (hangingClient) TestConnection(ctx context.Context) (*notifier.SendResult, error) {
	<-ctx.Done()
	return &notifier.SendResult{Success: false, Error: "send email: " + ctx.Err().Error()}, nil
}

type hangingFactory struct{}

func (hangingFactory) CreateClient(notifier.Config) (notifier.Client, error) {
	return hangingClient{}, nil
}

// notifRepo keeps one integration in memory.
type notifRepo struct {
	integrationdom.Repository
	intg    *integrationdom.Integration
	updates int
}

func (r *notifRepo) GetByID(_ context.Context, id shared.ID) (*integrationdom.Integration, error) {
	if r.intg == nil || r.intg.ID() != id {
		return nil, integrationdom.ErrIntegrationNotFound
	}
	return r.intg, nil
}

func (r *notifRepo) Update(ctx context.Context, intg *integrationdom.Integration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.updates++
	r.intg = intg
	return nil
}

// A connection test whose service never answers ends within
// notificationTestTimeout, well before the request timeout, and the
// integration is saved with the failure (INTEGRATION_UNREACHABLE) instead of
// the request ending in 504 TIMEOUT with the result unknown.
func TestNotificationTest_BoundedAndRecorded(t *testing.T) {
	prev := notificationTestTimeout
	notificationTestTimeout = 50 * time.Millisecond
	t.Cleanup(func() { notificationTestTimeout = prev })

	tenant := shared.NewID()
	intg := integrationdom.NewIntegration(shared.NewID(), tenant, "Security mailing list",
		integrationdom.CategoryNotification, integrationdom.ProviderEmail, integrationdom.AuthTypeToken)
	repo := &notifRepo{intg: intg}
	s := &IntegrationService{repo: repo, encryptor: crypto.NewNoOpEncryptor(), logger: logger.NewNop(),
		notificationFactory: hangingFactory{}, testRateLimitMap: map[string]time.Time{}}
	if err := s.setEmailCredentials(intg, smtpCredsJSON+`}`, false); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	got, err := s.TestNotificationIntegration(context.Background(), intg.ID().String(), tenant.String())
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the connection test took %s, want it bounded", d)
	}
	if repo.updates == 0 {
		t.Fatal("the failed test was not saved on the integration")
	}
	if got.Status() != integrationdom.StatusError || got.StatusMessage() == "" ||
		got.StatusCode() != string(apierror.CodeIntegrationUnreachable) {
		t.Fatalf("status = %s %q (%s), want error INTEGRATION_UNREACHABLE", got.Status(), got.StatusMessage(), got.StatusCode())
	}
}
