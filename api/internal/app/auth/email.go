package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	emaildom "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TenantSMTPResolver resolves per-tenant SMTP configuration from integrations.
// Returns nil if tenant has no custom SMTP config (fallback to system default).
type TenantSMTPResolver interface {
	GetTenantSMTPConfig(ctx context.Context, tenantID string) (*emaildom.Config, error)
}

// EmailService handles sending emails for various application events.
// Supports per-tenant SMTP via TenantSMTPResolver: if a tenant has a custom
// email integration configured, it uses that SMTP server instead of the system default.
type EmailService struct {
	sender     emaildom.Sender // System-wide default sender
	tenantSMTP TenantSMTPResolver
	config     config.SMTPConfig
	appName    string
	logger     *logger.Logger
}

// NewEmailService creates a new EmailService.
func NewEmailService(sender emaildom.Sender, cfg config.SMTPConfig, appName string, log *logger.Logger) *EmailService {
	return &EmailService{
		sender:  sender,
		config:  cfg,
		appName: appName,
		logger:  log.With("service", "email"),
	}
}

// SetTenantSMTPResolver sets the per-tenant SMTP resolver.
func (s *EmailService) SetTenantSMTPResolver(resolver TenantSMTPResolver) {
	s.tenantSMTP = resolver
}

// SendReport emails an already-rendered HTML report to explicit recipients,
// using the tenant's SMTP if configured (else the system default). Used by the
// scheduled-report controller. No-op (returns nil) when there are no recipients;
// errors if no SMTP sender is configured.
func (s *EmailService) SendReport(ctx context.Context, tenantID string, to []string, subject, htmlBody string) error {
	if len(to) == 0 {
		return nil
	}
	sender := s.getSenderForTenant(ctx, tenantID)
	if sender == nil || !sender.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	return sender.Send(ctx, &emaildom.Message{
		To:      to,
		Subject: subject,
		Body:    htmlBody,
		IsHTML:  true,
	})
}

// getSenderForTenant returns a per-tenant SMTP sender if configured, or the default sender.
func (s *EmailService) getSenderForTenant(ctx context.Context, tenantID string) emaildom.Sender {
	if s.tenantSMTP == nil || tenantID == "" {
		return s.sender
	}

	cfg, err := s.tenantSMTP.GetTenantSMTPConfig(ctx, tenantID)
	if err != nil {
		s.logger.Debug("no tenant SMTP config, using system default", "tenant_id", logSafe(tenantID))
		return s.sender
	}
	if cfg == nil {
		return s.sender
	}

	return emaildom.NewSMTPSender(*cfg)
}

// IsConfigured returns true if email service is properly configured.
func (s *EmailService) IsConfigured() bool {
	return s.sender != nil && s.sender.IsConfigured()
}

// HasSystemSMTP implements SMTPAvailabilityCheck.
// Returns true if the system-wide SMTP sender is configured.
func (s *EmailService) HasSystemSMTP() bool {
	return s.IsConfigured()
}

// HasTenantSMTP implements SMTPAvailabilityCheck.
// Returns true if the given tenant has a custom SMTP integration configured.
// tenantID may be empty for self-registration without tenant context.
func (s *EmailService) HasTenantSMTP(ctx context.Context, tenantID string) bool {
	if s.tenantSMTP == nil || tenantID == "" {
		return false
	}
	cfg, err := s.tenantSMTP.GetTenantSMTPConfig(ctx, tenantID)
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Host != ""
}

// SendVerificationEmail sends an email verification link to a user.
func (s *EmailService) SendVerificationEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping verification email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	// The token goes in the URL fragment (as for invitations): the browser
	// never sends it to a server. The web app's /verify-email page reads it.
	verificationURL := fmt.Sprintf("%s/verify-email#token=%s", strings.TrimSuffix(s.config.BaseURL, "/"), url.QueryEscape(token))

	data := emaildom.VerifyEmailData{
		UserName:        userName,
		Email:           userEmail,
		VerificationURL: verificationURL,
		ExpiresIn:       formatDuration(expiresIn),
		AppName:         s.appName,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplateVerifyEmail, data); err != nil {
		s.logger.Error("failed to send verification email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.Info("verification email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendPasswordResetEmail sends a password reset link to a user.
func (s *EmailService) SendPasswordResetEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password reset email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.config.BaseURL, token)

	data := emaildom.PasswordResetData{
		UserName:    userName,
		Email:       userEmail,
		ResetURL:    resetURL,
		ExpiresIn:   formatDuration(expiresIn),
		AppName:     s.appName,
		IPAddress:   ipAddress,
		RequestedAt: time.Now().Format("January 2, 2006 at 3:04 PM MST"),
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplatePasswordReset, data); err != nil {
		s.logger.Error("failed to send password reset email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.logger.Info("password reset email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendPasswordChangedEmail sends a notification that the password was changed.
func (s *EmailService) SendPasswordChangedEmail(ctx context.Context, userEmail, userName, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password changed email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	data := emaildom.PasswordChangedData{
		UserName:  userName,
		Email:     userEmail,
		ChangedAt: time.Now().Format("January 2, 2006 at 3:04 PM MST"),
		IPAddress: ipAddress,
		AppName:   s.appName,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplatePasswordChanged, data); err != nil {
		s.logger.Error("failed to send password changed email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	s.logger.Info("password changed email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *EmailService) SendWelcomeEmail(ctx context.Context, userEmail, userName string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping welcome email",
			"email", logSafe(userEmail),
		)
		return nil
	}

	loginURL := fmt.Sprintf("%s/login", strings.TrimSuffix(s.config.BaseURL, "/"))

	data := emaildom.WelcomeData{
		UserName: userName,
		Email:    userEmail,
		LoginURL: loginURL,
		AppName:  s.appName,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, emaildom.TemplateWelcome, data); err != nil {
		s.logger.Error("failed to send welcome email",
			"email", logSafe(userEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	s.logger.Info("welcome email sent",
		"email", logSafe(userEmail),
	)
	return nil
}

// SendMemberSuspendedEmail notifies a user that their tenant
// access has been suspended. Uses per-tenant SMTP if configured.
// Best-effort: returns nil and logs a warning if email is not
// configured for the tenant — the suspend operation should succeed
// even when the user can't be notified.
func (s *EmailService) SendMemberSuspendedEmail(
	ctx context.Context,
	recipientEmail, recipientName, teamName, actorName, tenantID string,
) error {
	sender := s.sender
	if tenantID != "" {
		sender = s.getSenderForTenant(ctx, tenantID)
	}
	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping member suspended email",
			"email", logSafe(recipientEmail), "tenant_id", logSafe(tenantID))
		return nil
	}

	data := emaildom.MemberStatusChangeData{
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateMemberSuspended, data); err != nil {
		s.logger.Error("failed to send member suspended email",
			"email", logSafe(recipientEmail), "error", err)
		return fmt.Errorf("failed to send member suspended email: %w", err)
	}

	s.logger.Info("member suspended email sent",
		"email", logSafe(recipientEmail), "team", logSafe(teamName))
	return nil
}

// SendMemberReactivatedEmail notifies a user that their access
// has been restored. Same best-effort semantics as
// SendMemberSuspendedEmail.
func (s *EmailService) SendMemberReactivatedEmail(
	ctx context.Context,
	recipientEmail, recipientName, teamName, actorName, tenantID string,
) error {
	sender := s.sender
	if tenantID != "" {
		sender = s.getSenderForTenant(ctx, tenantID)
	}
	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping member reactivated email",
			"email", logSafe(recipientEmail), "tenant_id", logSafe(tenantID))
		return nil
	}

	data := emaildom.MemberStatusChangeData{
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateMemberReactivated, data); err != nil {
		s.logger.Error("failed to send member reactivated email",
			"email", logSafe(recipientEmail), "error", err)
		return fmt.Errorf("failed to send member reactivated email: %w", err)
	}

	s.logger.Info("member reactivated email sent",
		"email", logSafe(recipientEmail), "team", logSafe(teamName))
	return nil
}

// CanDeliverTo reports whether an email can be sent on behalf of tenantID
// (the tenant's own SMTP integration, else the system SMTP).
func (s *EmailService) CanDeliverTo(ctx context.Context, tenantID string) bool {
	sender := s.getSenderForTenant(ctx, tenantID)
	return sender != nil && sender.IsConfigured()
}

// AccountSetupURL is the UI page that consumes a one-time set-password token.
func (s *EmailService) AccountSetupURL(token string) string {
	return fmt.Sprintf("%s/set-password?token=%s", strings.TrimSuffix(s.config.BaseURL, "/"), token)
}

// SendAccountSetupEmail sends the one-time set-password link for an account an
// administrator created. Unlike the best-effort notifications it returns an
// error when no sender is configured, so the caller can fall back to showing
// the link to the administrator instead of silently dropping it.
func (s *EmailService) SendAccountSetupEmail(ctx context.Context, tenantID, recipientEmail, recipientName, teamName, token string, expiresIn time.Duration) error {
	sender := s.getSenderForTenant(ctx, tenantID)
	if sender == nil || !sender.IsConfigured() {
		return fmt.Errorf("email: no SMTP sender configured")
	}
	data := emaildom.AccountSetupData{
		UserName:  recipientName,
		TeamName:  teamName,
		SetupURL:  s.AccountSetupURL(token),
		ExpiresIn: formatDuration(expiresIn),
		AppName:   s.appName,
	}
	// tenantID reaches here from the request path; strip line breaks before
	// logging it (CWE-117).
	logTenant := logSafe(tenantID)
	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateAccountSetup, data); err != nil {
		s.logger.Error("failed to send account setup email", "tenant_id", logTenant)
		return fmt.Errorf("failed to send account setup email: %w", err)
	}
	s.logger.Info("account setup email sent", "tenant_id", logTenant)
	return nil
}

// SendTeamInvitationEmail sends a team invitation email.
// Uses per-tenant SMTP if configured, otherwise falls back to system SMTP.
func (s *EmailService) SendTeamInvitationEmail(ctx context.Context, recipientEmail, inviterName, teamName, token string, expiresIn time.Duration, tenantID ...string) error {
	// Resolve sender: per-tenant or system default
	sender := s.sender
	if len(tenantID) > 0 && tenantID[0] != "" {
		sender = s.getSenderForTenant(ctx, tenantID[0])
	}

	if sender == nil || !sender.IsConfigured() {
		s.logger.Warn("email service not configured, skipping team invitation email",
			"email", logSafe(recipientEmail),
		)
		return nil
	}

	// The token goes in the URL fragment, which the browser never sends to a
	// server: it stays out of access logs, proxies and Referer headers
	// (RFC-041). The web app reads it from the fragment and removes it.
	invitationURL := fmt.Sprintf("%s/invitations#token=%s", s.config.BaseURL, url.QueryEscape(token))

	data := emaildom.TeamInvitationData{
		InviterName:   inviterName,
		TeamName:      teamName,
		InvitationURL: invitationURL,
		ExpiresIn:     formatDuration(expiresIn),
		AppName:       s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, emaildom.TemplateTeamInvitation, data); err != nil {
		s.logger.Error("failed to send team invitation email",
			"email", logSafe(recipientEmail),
			"error", err,
		)
		return fmt.Errorf("failed to send team invitation email: %w", err)
	}

	s.logger.Info("team invitation email sent",
		"email", logSafe(recipientEmail),
		"team", teamName,
		"tenant_smtp", len(tenantID) > 0 && tenantID[0] != "",
	)
	return nil
}

// formatDuration formats a duration into a human-readable string.
func formatDuration(d time.Duration) string {
	if d >= 24*time.Hour {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "24 hours"
		}
		return fmt.Sprintf("%d days", days)
	}
	if d >= time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	if d >= time.Minute {
		minutes := int(d.Minutes())
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}
	return d.String()
}

// The methods below make EmailService an auth.SecurityNotifier. They send in
// the background (the change they report is already committed) and only log
// failures, so a slow or broken SMTP server never fails the user's request.

// NotifyMFADisabled tells the user 2FA was turned off on their account.
func (s *EmailService) NotifyMFADisabled(ctx context.Context, userEmail, userName, ipAddress string) {
	s.sendSecurityNotice(ctx, userEmail, userName, ipAddress,
		"Two-factor authentication was turned off",
		"Two-factor authentication was just turned off for your account. Signing in now needs only your password.")
}

// NotifyRecoveryCodeUsed tells the user a recovery code was used to sign in.
func (s *EmailService) NotifyRecoveryCodeUsed(ctx context.Context, userEmail, userName, ipAddress string, remaining int) {
	s.sendSecurityNotice(ctx, userEmail, userName, ipAddress,
		"A recovery code was used to sign in",
		fmt.Sprintf("One of your two-factor recovery codes was just used to sign in to your account. You have %d unused recovery codes left; generate new ones from your account settings if you are running low.", remaining))
}

// NotifyPasswordChanged sends the existing password-changed email.
func (s *EmailService) NotifyPasswordChanged(ctx context.Context, userEmail, userName, ipAddress string) {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		_ = s.SendPasswordChangedEmail(bg, userEmail, userName, ipAddress)
	}()
}

// NotifySSOChangePending tells an organization owner that a platform
// administrator proposed an SSO change that waits for their approval. summary
// never contains a secret.
func (s *EmailService) NotifySSOChangePending(ctx context.Context, ownerEmail, ownerName, orgName, summary string) {
	s.sendSecurityNotice(ctx, ownerEmail, ownerName, "",
		"An SSO change for "+orgName+" is waiting for your approval",
		summary+" Review it under Settings > SSO approvals. If you did not expect this change, reject it.")
}

func (s *EmailService) sendSecurityNotice(ctx context.Context, userEmail, userName, ipAddress, subject, message string) {
	if !s.IsConfigured() {
		return
	}
	data := emaildom.SecurityNoticeData{
		UserName:   userName,
		Email:      userEmail,
		Subject:    subject,
		Message:    message,
		OccurredAt: time.Now().UTC().Format("January 2, 2006 at 3:04 PM MST"),
		IPAddress:  ipAddress,
		AppName:    s.appName,
	}
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if err := s.sender.SendTemplate(bg, userEmail, emaildom.TemplateSecurityNotice, data); err != nil {
			s.logger.Error("failed to send security notice email", "error", err)
		}
	}()
}

// logSafe strips line breaks from a caller-supplied value before it is
// logged, so it cannot forge log entries (CWE-117). strings.ReplaceAll on
// \n and \r is the sanitizer CodeQL recognizes.
func logSafe(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}
