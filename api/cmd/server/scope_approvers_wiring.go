package main

import (
	"context"
	"errors"
	"html"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/finding"
	scangovapp "github.com/openctemio/openctem/api/internal/app/scangov"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// scopeTOTP is the fresh authenticator check for an owner's own approval of
// a scope entry (RFC-054 §7), in the scope service's error terms.
type scopeTOTP struct{ auth *auth.AuthService }

var _ scopeapp.TOTPVerifier = scopeTOTP{}

func (v scopeTOTP) VerifyFreshTOTP(ctx context.Context, userID, code string) error {
	err := v.auth.VerifyFreshTOTP(ctx, userID, code)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrTOTPNotEnrolled):
		return scopedom.ErrSelfApprovalNeedsTOTP
	case errors.Is(err, auth.ErrStepUpFailed), errors.Is(err, auth.ErrAccountLocked):
		return scopedom.ErrSelfApprovalBadCode
	}
	return err
}

// scopeApprovalMailer emails scope approval requests through the
// organization's SMTP (or the system's). Asynchronous: the request must not
// wait on SMTP.
type scopeApprovalMailer struct {
	email *auth.EmailService
	log   *logger.Logger
}

var _ scopeapp.ApprovalMailer = scopeApprovalMailer{}

func (m scopeApprovalMailer) SendScopeApprovalMail(_ context.Context, tenantID string, to []string, subject, htmlBody string) {
	if m.email == nil || len(to) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, tenantID, to, subject, htmlBody); err != nil {
			m.log.Warn("scope approval email failed", "error", logger.SanitizeError(err))
		}
	}()
}

// wireScopeApprovers gives the scope service its approver directory, the
// authenticator check, the approval emails and the channels.
func wireScopeApprovers(svc *Services, repos *Repositories, dir *postgres.ScopeActorRepository, webBaseURL string, log *logger.Logger) {
	if svc.Scope == nil {
		return
	}
	// The platform policy for scan approval and the organization's scan
	// approval mode (RFC-073): scope entries need approval only in Strict;
	// an unreadable mode counts as Strict for them.
	if repos != nil && repos.ScanPolicy != nil {
		svc.ScanPolicy = scanpolicy.NewService(repos.ScanPolicy, repos.AdminAuditLog, repos.Admin,
			scopePolicyMailer{email: svc.Email, log: log}, svc.Scope, log)
		if svc.Tenant != nil {
			svc.ScanPolicy.SetSettings(svc.Tenant)
			// The organization owner's shared sensor opt-out (RFC-100 §5).
			svc.ScanPolicy.SetSharedSensorsOptOut(svc.Tenant)
		}
		svc.Scope.SetGovernance(svc.ScanPolicy)
		// Verified domain before platform sensors scan (RFC-054 §8.1): a
		// platform setting, read at each check (cached briefly).
		if svc.Scan != nil {
			svc.Scan.SetProofPolicy(svc.ScanPolicy)
		}
		// Scope entry tier ceilings are in force only in Strict: the
		// dispatch gate reads the mode, and a mode change that crosses
		// Strict is recorded with the job signer's ledger.
		svc.ScanPolicy.SetTierCeilings(svc.Scope)
		if svc.ActiveGate != nil {
			svc.ActiveGate.SetTierPolicy(svc.ScanPolicy)
			// Unclassified assets (RFC-054 §16): the organization's setting,
			// off under Strict; an unreadable setting is off.
			if svc.Tenant != nil {
				gov, tenants := svc.ScanPolicy, svc.Tenant
				svc.ActiveGate.SetUnclassified(func(ctx context.Context, tenantID shared.ID) (string, error) {
					mode, _ := gov.ScanGovernanceMode(ctx, tenantID)
					ss, err := tenants.GetScopeSettings(ctx, tenantID.String())
					if err != nil || ss == nil {
						return tenantdom.UnclassifiedOff, err
					}
					return scangov.UnclassifiedMode(mode, ss.Unclassified()), nil
				}, repos.Attribution)
			}
		}

		wireScanGovernance(svc, repos, log)
	}
	var totp scopeapp.TOTPVerifier
	if svc.Auth != nil {
		totp = scopeTOTP{auth: svc.Auth}
	}
	var mail scopeapp.ApprovalMailer
	if svc.Email != nil {
		mail = scopeApprovalMailer{email: svc.Email, log: log}
	}
	var channels scopeapp.ChannelNotifier
	if svc.Outbox != nil {
		channels = svc.Outbox
	}
	svc.Scope.SetApprovers(dir, totp, mail, channels, webBaseURL)
	if svc.Audit != nil {
		svc.Scope.SetAuditor(svc.Audit)
	}
}

// scopePolicyMailer emails the other platform administrators when the scan
// approval policy changes (asynchronous; the service also writes a WARN line
// with alert=scan_approval_policy_changed for log-based alerting).
type scopePolicyMailer struct {
	email *auth.EmailService
	log   *logger.Logger
}

var _ scanpolicy.Mailer = scopePolicyMailer{}

func (m scopePolicyMailer) NotifyScopePolicyChanged(_ context.Context, to []string, subject, body string) {
	if m.email == nil || !m.email.IsConfigured() || len(to) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", to, subject, "<p>"+html.EscapeString(body)+"</p>"); err != nil {
			m.log.Warn("scan policy email failed", "error", logger.SanitizeError(err))
		}
	}()
}

// wireScanGovernance builds scan approval governance (RFC-073): the settings,
// the approval requests, the approver directory, the authenticator check for
// an owner's own approval, notifications and audit, and the gate every scan
// run passes.
func wireScanGovernance(svc *Services, repos *Repositories, log *logger.Logger) {
	if svc.Tenant == nil {
		return
	}
	svc.ScanGovernance = scangovapp.NewService(svc.ScanPolicy, svc.Tenant, log)
	svc.ScanGovernance.SetTierCeilings(svc.Scope)
	if repos.ScanApproval != nil {
		svc.ScanGovernance.SetRequests(repos.ScanApproval)
		var totp scangovapp.TOTPVerifier
		if svc.Auth != nil {
			totp = scopeTOTP{auth: svc.Auth}
		}
		svc.ScanGovernance.SetApprovers(repos.ScanApproval, totp)
		svc.ScanGovernance.SetRequesters(repos.ScanApproval, svc.Tenant)
	}
	if svc.Notification != nil {
		svc.ScanGovernance.SetNotifier(svc.Notification)
	}
	if svc.Audit != nil {
		svc.ScanGovernance.SetAudit(svc.Audit)
	}
	if svc.Scan != nil {
		svc.ScanGovernance.SetScans(svc.Scan)
		svc.ScanGovernance.SetScanLister(svc.Scan)
		svc.Scan.SetApprovalGate(svc.ScanGovernance, repos.ScanApproval)
	}
}

// findingApprovalMailer emails finding approval requests through the
// organization's SMTP (or the system's), asynchronously.
type findingApprovalMailer struct {
	email *auth.EmailService
	log   *logger.Logger
}

var _ finding.FindingApprovalMailer = findingApprovalMailer{}

func (m findingApprovalMailer) SendFindingApprovalMail(_ context.Context, tenantID string, to []string, subject, htmlBody string) {
	if m.email == nil || len(to) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, tenantID, to, subject, htmlBody); err != nil {
			m.log.Warn("finding approval email failed", "error", logger.SanitizeError(err))
		}
	}()
}

// wireFindingApprovers tells the members who may approve a finding
// false-positive or accepted-risk request about it (in-app and email).
func wireFindingApprovers(svc *Services, dir *postgres.ScopeActorRepository, webBaseURL string, log *logger.Logger) {
	if svc.Vulnerability == nil || dir == nil {
		return
	}
	var inApp finding.ApprovalInApp
	if svc.Notification != nil {
		inApp = svc.Notification
	}
	var mail finding.FindingApprovalMailer
	if svc.Email != nil {
		mail = findingApprovalMailer{email: svc.Email, log: log}
	}
	svc.Vulnerability.SetApprovalNotifier(dir, inApp, mail, webBaseURL)
	// The sole member's own approval: the owner check, a fresh authenticator
	// code, and the backup contact from the organization's settings.
	var totp finding.ApprovalTOTPVerifier
	if svc.Auth != nil {
		totp = freshTOTP{auth: svc.Auth,
			notEnrolled: vulnerability.ErrSoloApprovalNeedsTOTP, badCode: vulnerability.ErrSoloApprovalBadCode}
	}
	var settings finding.ApprovalSettingsReader
	if svc.Tenant != nil {
		settings = svc.Tenant
	}
	svc.Vulnerability.SetSoloApproval(dir, totp, settings)
}

// freshTOTP is the fresh authenticator check of an owner's own approval of
// an exposure disposition or a suppression rule, answering the caller's own
// errors for "no authenticator" and "bad code".
type freshTOTP struct {
	auth        *auth.AuthService
	notEnrolled error
	badCode     error
}

func (v freshTOTP) VerifyFreshTOTP(ctx context.Context, userID, code string) error {
	err := v.auth.VerifyFreshTOTP(ctx, userID, code)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrTOTPNotEnrolled):
		return v.notEnrolled
	case errors.Is(err, auth.ErrStepUpFailed), errors.Is(err, auth.ErrAccountLocked):
		return v.badCode
	}
	return err
}

// wireSelfApprovalTOTP gives the exposure disposition gate and the
// suppression service the authenticator check an owner's own approval needs.
// Without it every own approval is refused (fail closed).
func wireSelfApprovalTOTP(svc *Services) {
	if svc.Auth == nil {
		return
	}
	if svc.Exposure != nil {
		svc.Exposure.SetDispositionTOTP(freshTOTP{auth: svc.Auth,
			notEnrolled: exposuredom.ErrDispositionSelfApprovalNeedsTOTP, badCode: exposuredom.ErrDispositionSelfApprovalBadCode})
	}
	if svc.Suppression != nil {
		svc.Suppression.SetTOTPVerifier(freshTOTP{auth: svc.Auth,
			notEnrolled: suppression.ErrSelfApprovalNeedsTOTP, badCode: suppression.ErrSelfApprovalBadCode})
	}
}
