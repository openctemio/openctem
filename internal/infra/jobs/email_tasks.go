// Package jobs provides background job definitions and handlers using Asynq.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// Task types for email jobs
const (
	TypeEmailTeamInvitation = "email:team_invitation"
	TypeEmailWelcome        = "email:welcome"
	TypeEmailVerification   = "email:verification"
	TypeEmailPasswordReset  = "email:password_reset"
)

// TeamInvitationPayload contains data for sending team invitation emails.
type TeamInvitationPayload struct {
	RecipientEmail string        `json:"recipient_email"`
	InviterName    string        `json:"inviter_name"`
	TeamName       string        `json:"team_name"`
	Token          string        `json:"token"`
	ExpiresIn      time.Duration `json:"expires_in"`
	InvitationID   string        `json:"invitation_id"`
	TenantID       string        `json:"tenant_id"`
}

// WelcomeEmailPayload contains data for sending welcome emails.
type WelcomeEmailPayload struct {
	UserEmail string `json:"user_email"`
	UserName  string `json:"user_name"`
	UserID    string `json:"user_id"`
}

// VerificationEmailPayload contains data for sending verification emails.
type VerificationEmailPayload struct {
	UserEmail string        `json:"user_email"`
	UserName  string        `json:"user_name"`
	Token     string        `json:"token"`
	ExpiresIn time.Duration `json:"expires_in"`
	UserID    string        `json:"user_id"`
}

// PasswordResetPayload contains data for sending password reset emails.
type PasswordResetPayload struct {
	UserEmail string        `json:"user_email"`
	UserName  string        `json:"user_name"`
	Token     string        `json:"token"`
	ExpiresIn time.Duration `json:"expires_in"`
	IPAddress string        `json:"ip_address"`
	UserID    string        `json:"user_id"`
}

// NewTeamInvitationTask creates a new team invitation email task.
func NewTeamInvitationTask(payload TeamInvitationPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal team invitation payload: %w", err)
	}
	return asynq.NewTask(
		TypeEmailTeamInvitation,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Second),
		asynq.Queue("email"),
	), nil
}

// NewWelcomeEmailTask creates a new welcome email task.
func NewWelcomeEmailTask(payload WelcomeEmailPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal welcome email payload: %w", err)
	}
	return asynq.NewTask(
		TypeEmailWelcome,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Second),
		asynq.Queue("email"),
	), nil
}

// NewVerificationEmailTask creates a new verification email task.
func NewVerificationEmailTask(payload VerificationEmailPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification email payload: %w", err)
	}
	return asynq.NewTask(
		TypeEmailVerification,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Second),
		asynq.Queue("email"),
	), nil
}

// NewPasswordResetTask creates a new password reset email task.
func NewPasswordResetTask(payload PasswordResetPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal password reset payload: %w", err)
	}
	return asynq.NewTask(
		TypeEmailPasswordReset,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(30*time.Second),
		asynq.Queue("email"),
	), nil
}

// EmailTaskHandler handles email task processing.
type EmailTaskHandler struct {
	emailService *app.EmailService
	logger       *logger.Logger
}

// NewEmailTaskHandler creates a new email task handler.
func NewEmailTaskHandler(emailService *app.EmailService, log *logger.Logger) *EmailTaskHandler {
	return &EmailTaskHandler{
		emailService: emailService,
		logger:       log.With("handler", "email_tasks"),
	}
}

// HandleTeamInvitation processes team invitation email tasks.
func (h *EmailTaskHandler) HandleTeamInvitation(ctx context.Context, t *asynq.Task) error {
	var payload TeamInvitationPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	h.logger.Info("processing team invitation email",
		"email", payload.RecipientEmail,
		"team", payload.TeamName,
		"invitation_id", payload.InvitationID,
	)

	err := h.emailService.SendTeamInvitationEmail(
		ctx,
		payload.RecipientEmail,
		payload.InviterName,
		payload.TeamName,
		payload.Token,
		payload.ExpiresIn,
	)
	if err != nil {
		h.logger.Error("failed to send team invitation email",
			"email", payload.RecipientEmail,
			"error", err,
		)
		return err
	}

	h.logger.Info("team invitation email sent successfully",
		"email", payload.RecipientEmail,
		"team", payload.TeamName,
	)
	return nil
}

// HandleWelcomeEmail processes welcome email tasks.
func (h *EmailTaskHandler) HandleWelcomeEmail(ctx context.Context, t *asynq.Task) error {
	var payload WelcomeEmailPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	h.logger.Info("processing welcome email",
		"email", payload.UserEmail,
		"user_id", payload.UserID,
	)

	err := h.emailService.SendWelcomeEmail(ctx, payload.UserEmail, payload.UserName)
	if err != nil {
		h.logger.Error("failed to send welcome email",
			"email", payload.UserEmail,
			"error", err,
		)
		return err
	}

	h.logger.Info("welcome email sent successfully",
		"email", payload.UserEmail,
	)
	return nil
}

// HandleVerificationEmail processes verification email tasks.
func (h *EmailTaskHandler) HandleVerificationEmail(ctx context.Context, t *asynq.Task) error {
	var payload VerificationEmailPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	h.logger.Info("processing verification email",
		"email", payload.UserEmail,
		"user_id", payload.UserID,
	)

	err := h.emailService.SendVerificationEmail(
		ctx,
		payload.UserEmail,
		payload.UserName,
		payload.Token,
		payload.ExpiresIn,
	)
	if err != nil {
		h.logger.Error("failed to send verification email",
			"email", payload.UserEmail,
			"error", err,
		)
		return err
	}

	h.logger.Info("verification email sent successfully",
		"email", payload.UserEmail,
	)
	return nil
}

// HandlePasswordReset processes password reset email tasks.
func (h *EmailTaskHandler) HandlePasswordReset(ctx context.Context, t *asynq.Task) error {
	var payload PasswordResetPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	h.logger.Info("processing password reset email",
		"email", payload.UserEmail,
		"user_id", payload.UserID,
	)

	err := h.emailService.SendPasswordResetEmail(
		ctx,
		payload.UserEmail,
		payload.UserName,
		payload.Token,
		payload.ExpiresIn,
		payload.IPAddress,
	)
	if err != nil {
		h.logger.Error("failed to send password reset email",
			"email", payload.UserEmail,
			"error", err,
		)
		return err
	}

	h.logger.Info("password reset email sent successfully",
		"email", payload.UserEmail,
	)
	return nil
}
