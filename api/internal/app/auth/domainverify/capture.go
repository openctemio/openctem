package domainverify

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// captureNoticeLimit bounds the accounts told in one go.
const captureNoticeLimit = 5000

// DomainAccountLister lists active accounts on a domain outside an
// organization.
type DomainAccountLister interface {
	ListActiveEmailsOnDomain(ctx context.Context, domain string, includeSubdomains bool, excludeTenant shared.ID, limit int) ([]string, error)
}

// CaptureMailer sends one account its notice that the organization claiming
// its domain now manages accounts on it.
type CaptureMailer func(ctx context.Context, to, domain string) error

// NotifyCapture tells the existing accounts on a domain (outside the claiming
// organization) that the organization now manages it: their next sign-in may
// go through its SSO, or they may not create organizations. Their other
// organizations and data are never moved or shown to the claimant. Each
// address gets its own message. Sent once per claim (capture_notified_at).
func (s *Service) NotifyCapture(ctx context.Context, vd *verifieddomain.VerifiedDomain, lister DomainAccountLister, send CaptureMailer) (int, error) {
	if vd.CaptureNotifiedAt() != nil || !vd.SignupPolicy().Manages() {
		return 0, nil
	}
	emails, err := lister.ListActiveEmailsOnDomain(ctx, vd.Domain(), vd.SignupPolicy().IncludeSubdomains, vd.TenantID(), captureNoticeLimit)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, e := range emails {
		if err := send(ctx, e, vd.Domain()); err != nil {
			s.logger.Warn("domain capture notice not sent", "domain", vd.Domain(), "error", err)
			continue
		}
		sent++
	}
	vd.MarkCaptureNotified(time.Now())
	if err := s.repo.Update(ctx, vd); err != nil {
		return sent, err
	}
	s.logger.Info("domain capture notice sent", "domain", vd.Domain(), "accounts", sent)
	return sent, nil
}
