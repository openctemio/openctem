package main

import (
	"context"
	"errors"
	"html"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopepolicy"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
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
	// The platform approval policy (RFC-054 §12.6): fail closed to
	// `required` when it cannot be read.
	if repos != nil && repos.ScopePolicy != nil {
		svc.ScopePolicy = scopepolicy.NewService(repos.ScopePolicy, repos.AdminAuditLog, repos.Admin,
			scopePolicyMailer{email: svc.Email, log: log}, svc.Scope, log)
		svc.Scope.SetApprovalPolicy(svc.ScopePolicy)
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

// scopePolicyMailer emails the other platform administrators when the scope
// approval policy changes (asynchronous; the service also writes a WARN line
// with alert=scope_approval_policy_changed for log-based alerting).
type scopePolicyMailer struct {
	email *auth.EmailService
	log   *logger.Logger
}

var _ scopepolicy.Mailer = scopePolicyMailer{}

func (m scopePolicyMailer) NotifyScopePolicyChanged(_ context.Context, to []string, subject, body string) {
	if m.email == nil || !m.email.IsConfigured() || len(to) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.email.SendReport(ctx, "", to, subject, "<p>"+html.EscapeString(body)+"</p>"); err != nil {
			m.log.Warn("scope policy email failed", "error", logger.SanitizeError(err))
		}
	}()
}
