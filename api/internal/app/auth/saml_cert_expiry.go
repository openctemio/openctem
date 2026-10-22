package auth

// IdP certificate expiry alerts for per-organization SAML. Design:
// docs/architecture/saml-sso.md, "Certificate expiry".

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	samldom "github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
)

// samlCertNoticeDays are the days-before-expiry at which owners are alerted;
// 0 is the "has expired" alert.
var samlCertNoticeDays = []int{30, 7, 1, 0}

// SAMLCertOwners lists an organization's active owners.
type SAMLCertOwners interface {
	ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error)
}

// SAMLCertExpiryMailer emails an owner about an expiring IdP certificate.
type SAMLCertExpiryMailer interface {
	NotifySAMLCertificateExpiry(ctx context.Context, ownerEmail, ownerName, subject, message string)
}

type samlCertExpiryNotifier struct {
	store  samldom.CertificateExpiryStore
	owners SAMLCertOwners
	inApp  SSOChangeInAppNotifier
	mailer SAMLCertExpiryMailer
}

// SetCertExpiryAlerts wires the certificate-expiry sweep: the store it reads
// and marks, the owner list and the in-app notifier.
func (s *SAMLService) SetCertExpiryAlerts(store samldom.CertificateExpiryStore, owners SAMLCertOwners, inApp SSOChangeInAppNotifier) {
	s.expiry.store, s.expiry.owners, s.expiry.inApp = store, owners, inApp
}

// SetCertExpiryMailer also emails the owners (system SMTP).
func (s *SAMLService) SetCertExpiryMailer(m SAMLCertExpiryMailer) { s.expiry.mailer = m }

// CertificateNotAfter is the expiry of a stored IdP certificate (zero when it
// does not parse).
func CertificateNotAfter(certPEM string) time.Time {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}

// samlCertNoticeFor is the alert level for a certificate expiring at notAfter:
// the tightest of samlCertNoticeDays it has reached, or -1 when none.
func samlCertNoticeFor(notAfter, now time.Time) int {
	days := int(math.Ceil(notAfter.Sub(now).Hours() / 24))
	level := -1
	for _, d := range samlCertNoticeDays {
		if days <= d {
			level = d
		}
	}
	return level
}

// SweepCertificateExpiry alerts the owners of every organization whose enabled
// SAML IdP certificate reaches a new notice level (30, 7, 1 days, expired),
// once per level per certificate. It returns how many organizations were
// alerted. Without the alerts wired it does nothing.
func (s *SAMLService) SweepCertificateExpiry(ctx context.Context, now time.Time) (int, error) {
	if s.expiry.store == nil || s.expiry.owners == nil {
		return 0, nil
	}
	recs, err := s.expiry.store.ListEnabledCertificates(ctx, 500)
	if err != nil {
		return 0, err
	}
	alerted := 0
	for _, rec := range recs {
		cert, perr := parseCertificatePEM(rec.Certificate)
		if perr != nil {
			s.logger.Warn("saml certificate does not parse", "tenant_id", rec.TenantID.String())
			continue
		}
		level := samlCertNoticeFor(cert.NotAfter, now)
		if level < 0 || (rec.NoticeDays != nil && *rec.NoticeDays <= level) {
			continue
		}
		s.alertCertificateExpiry(ctx, rec.TenantID, cert, level, now)
		if err := s.expiry.store.SetCertificateNotice(ctx, rec.TenantID, level); err != nil {
			s.logger.Error("record saml certificate notice", "tenant_id", rec.TenantID.String(), "error", err)
			continue
		}
		alerted++
	}
	return alerted, nil
}

func (s *SAMLService) alertCertificateExpiry(ctx context.Context, tenantID shared.ID, cert *x509.Certificate, level int, now time.Time) {
	owners, err := s.expiry.owners.ListActiveOwners(ctx, tenantID)
	if err != nil {
		s.logger.Error("list owners for saml certificate notice", "tenant_id", tenantID.String(), "error", err)
		return
	}
	orgName := tenantID.String()
	if s.tenantRepo != nil {
		if t, terr := s.tenantRepo.GetByID(ctx, tenantID); terr == nil && t != nil {
			orgName = t.Name()
		}
	}
	date := cert.NotAfter.UTC().Format("2006-01-02")
	var title, body string
	if !cert.NotAfter.After(now) {
		title = "The SAML identity provider certificate has expired"
		body = fmt.Sprintf("The signing certificate of %s's SAML identity provider expired on %s. "+
			"SAML sign-in fails until the identity provider's current certificate is uploaded in the SAML settings.", orgName, date)
	} else {
		title = fmt.Sprintf("The SAML identity provider certificate expires in %d day(s)", max(level, 1))
		body = fmt.Sprintf("The signing certificate of %s's SAML identity provider expires on %s. "+
			"SAML sign-in stops working when it expires: ask the identity provider's administrator for the new certificate "+
			"and upload it in the SAML settings before then.", orgName, date)
	}
	for _, o := range owners {
		uid := o.UserID
		if s.expiry.inApp != nil {
			if err := s.expiry.inApp.Notify(ctx, notificationdom.NotificationParams{
				TenantID:         tenantID,
				Audience:         notificationdom.AudienceUser,
				AudienceID:       &uid,
				NotificationType: notificationdom.TypeSystemAlert,
				Title:            title,
				Body:             body,
				Severity:         notificationdom.SeverityHigh,
				ResourceType:     "saml_provider",
				URL:              "/settings/authentication",
			}); err != nil {
				s.logger.Error("notify owner of saml certificate expiry", "tenant_id", tenantID.String(), "error", err)
			}
		}
		if s.expiry.mailer != nil && o.Email != "" {
			s.expiry.mailer.NotifySAMLCertificateExpiry(ctx, o.Email, o.Name, title, body)
		}
	}
}
