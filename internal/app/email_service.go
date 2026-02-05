package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/logger"
)

// EmailService handles sending emails for various application events.
type EmailService struct {
	sender  email.Sender
	config  config.SMTPConfig
	appName string
	logger  *logger.Logger
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

// IsConfigured returns true if email service is properly configured.
func (s *EmailService) IsConfigured() bool {
	return s.sender != nil && s.sender.IsConfigured()
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

// SendTeamInvitationEmail sends a team invitation email.
func (s *EmailService) SendTeamInvitationEmail(ctx context.Context, recipientEmail, inviterName, teamName, token string, expiresIn time.Duration) error {
	if !s.IsConfigured() {
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

	if err := s.sender.SendTemplate(ctx, recipientEmail, email.TemplateTeamInvitation, data); err != nil {
		s.logger.Error("failed to send team invitation email",
			"email", recipientEmail,
			"error", err,
		)
		return fmt.Errorf("failed to send team invitation email: %w", err)
	}

	s.logger.Info("team invitation email sent",
		"email", recipientEmail,
		"team", teamName,
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
