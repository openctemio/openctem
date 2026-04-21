package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/logger"
)

// TenantSMTPResolver resolves per-tenant SMTP configuration from integrations.
// Returns nil if tenant has no custom SMTP config (fallback to system default).
type TenantSMTPResolver interface {
	GetTenantSMTPConfig(ctx context.Context, tenantID string) (*email.Config, error)
}

// EmailService handles sending emails for various application events.
// Supports per-tenant SMTP via TenantSMTPResolver: if a tenant has a custom
// email integration configured, it uses that SMTP server instead of the system default.
type EmailService struct {
	sender       email.Sender // System-wide default sender
	tenantSMTP   TenantSMTPResolver
	config       config.SMTPConfig
	appName      string
	logger       *logger.Logger
}

// NewEmailService creates a new EmailService.
func NewEmailService(sender email.Sender, cfg config.SMTPConfig, appName string, log *logger.Logger) *EmailService {
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

// getSenderForTenant returns a per-tenant SMTP sender if configured, or the default sender.
func (s *EmailService) getSenderForTenant(ctx context.Context, tenantID string) email.Sender {
	if s.tenantSMTP == nil || tenantID == "" {
		return s.sender
	}

	cfg, err := s.tenantSMTP.GetTenantSMTPConfig(ctx, tenantID)
	if err != nil {
		s.logger.Debug("no tenant SMTP config, using system default", "tenant_id", tenantID)
		return s.sender
	}
	if cfg == nil {
		return s.sender
	}

	return email.NewSMTPSender(*cfg)
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
			"email", userEmail,
		)
		return nil
	}

	verificationURL := fmt.Sprintf("%s/auth/verify-email?token=%s", s.config.BaseURL, token)

	data := email.VerifyEmailData{
		UserName:        userName,
		Email:           userEmail,
		VerificationURL: verificationURL,
		ExpiresIn:       formatDuration(expiresIn),
		AppName:         s.appName,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, email.TemplateVerifyEmail, data); err != nil {
		s.logger.Error("failed to send verification email",
			"email", userEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.Info("verification email sent",
		"email", userEmail,
	)
	return nil
}

// SendPasswordResetEmail sends a password reset link to a user.
func (s *EmailService) SendPasswordResetEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password reset email",
			"email", userEmail,
		)
		return nil
	}

	resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s", s.config.BaseURL, token)

	data := email.PasswordResetData{
		UserName:    userName,
		Email:       userEmail,
		ResetURL:    resetURL,
		ExpiresIn:   formatDuration(expiresIn),
		AppName:     s.appName,
		IPAddress:   ipAddress,
		RequestedAt: time.Now().Format("January 2, 2006 at 3:04 PM MST"),
	}

	if err := s.sender.SendTemplate(ctx, userEmail, email.TemplatePasswordReset, data); err != nil {
		s.logger.Error("failed to send password reset email",
			"email", userEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.logger.Info("password reset email sent",
		"email", userEmail,
	)
	return nil
}

// SendPasswordChangedEmail sends a notification that the password was changed.
func (s *EmailService) SendPasswordChangedEmail(ctx context.Context, userEmail, userName, ipAddress string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping password changed email",
			"email", userEmail,
		)
		return nil
	}

	supportURL := fmt.Sprintf("%s/support", s.config.BaseURL)

	data := email.PasswordChangedData{
		UserName:   userName,
		Email:      userEmail,
		ChangedAt:  time.Now().Format("January 2, 2006 at 3:04 PM MST"),
		IPAddress:  ipAddress,
		AppName:    s.appName,
		SupportURL: supportURL,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, email.TemplatePasswordChanged, data); err != nil {
		s.logger.Error("failed to send password changed email",
			"email", userEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	s.logger.Info("password changed email sent",
		"email", userEmail,
	)
	return nil
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *EmailService) SendWelcomeEmail(ctx context.Context, userEmail, userName string) error {
	if !s.IsConfigured() {
		s.logger.Warn("email service not configured, skipping welcome email",
			"email", userEmail,
		)
		return nil
	}

	loginURL := fmt.Sprintf("%s/auth/login", s.config.BaseURL)
	supportURL := fmt.Sprintf("%s/support", s.config.BaseURL)

	data := email.WelcomeData{
		UserName:   userName,
		Email:      userEmail,
		LoginURL:   loginURL,
		AppName:    s.appName,
		SupportURL: supportURL,
	}

	if err := s.sender.SendTemplate(ctx, userEmail, email.TemplateWelcome, data); err != nil {
		s.logger.Error("failed to send welcome email",
			"email", userEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	s.logger.Info("welcome email sent",
		"email", userEmail,
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
			"email", recipientEmail, "tenant_id", tenantID)
		return nil
	}

	data := email.MemberStatusChangeData{
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, email.TemplateMemberSuspended, data); err != nil {
		s.logger.Error("failed to send member suspended email",
			"email", recipientEmail, "error", err)
		return fmt.Errorf("failed to send member suspended email: %w", err)
	}

	s.logger.Info("member suspended email sent",
		"email", recipientEmail, "team", teamName)
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
			"email", recipientEmail, "tenant_id", tenantID)
		return nil
	}

	data := email.MemberStatusChangeData{
		UserName:  recipientName,
		TeamName:  teamName,
		ActorName: actorName,
		AppURL:    s.config.BaseURL,
		AppName:   s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, email.TemplateMemberReactivated, data); err != nil {
		s.logger.Error("failed to send member reactivated email",
			"email", recipientEmail, "error", err)
		return fmt.Errorf("failed to send member reactivated email: %w", err)
	}

	s.logger.Info("member reactivated email sent",
		"email", recipientEmail, "team", teamName)
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
			"email", recipientEmail,
		)
		return nil
	}

	invitationURL := fmt.Sprintf("%s/invitations/%s", s.config.BaseURL, token)

	data := email.TeamInvitationData{
		InviterName:   inviterName,
		TeamName:      teamName,
		InvitationURL: invitationURL,
		ExpiresIn:     formatDuration(expiresIn),
		AppName:       s.appName,
	}

	if err := sender.SendTemplate(ctx, recipientEmail, email.TemplateTeamInvitation, data); err != nil {
		s.logger.Error("failed to send team invitation email",
			"email", recipientEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send team invitation email: %w", err)
	}

	s.logger.Info("team invitation email sent",
		"email", recipientEmail,
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
