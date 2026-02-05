package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/pkg/logger"
)

// Client manages enqueueing background jobs using Asynq.
type Client struct {
	client *asynq.Client
	logger *logger.Logger
}

// ClientConfig contains configuration for the job client.
type ClientConfig struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

// NewClient creates a new job client for enqueueing tasks.
func NewClient(cfg ClientConfig, log *logger.Logger) (*Client, error) {
	redisOpt := asynq.RedisClientOpt{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}

	client := asynq.NewClient(redisOpt)

	return &Client{
		client: client,
		logger: log.With("component", "job_client"),
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// EnqueueTeamInvitation enqueues a team invitation email job.
func (c *Client) EnqueueTeamInvitation(ctx context.Context, payload TeamInvitationPayload) error {
	task, err := NewTeamInvitationTask(payload)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	info, err := c.client.EnqueueContext(ctx, task)
	if err != nil {
		c.logger.Error("failed to enqueue team invitation email",
			"email", payload.RecipientEmail,
			"error", err,
		)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.Info("team invitation email queued",
		"task_id", info.ID,
		"email", payload.RecipientEmail,
		"queue", info.Queue,
	)
	return nil
}

// EnqueueWelcomeEmail enqueues a welcome email job.
func (c *Client) EnqueueWelcomeEmail(ctx context.Context, payload WelcomeEmailPayload) error {
	task, err := NewWelcomeEmailTask(payload)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	info, err := c.client.EnqueueContext(ctx, task)
	if err != nil {
		c.logger.Error("failed to enqueue welcome email",
			"email", payload.UserEmail,
			"error", err,
		)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.Info("welcome email queued",
		"task_id", info.ID,
		"email", payload.UserEmail,
		"queue", info.Queue,
	)
	return nil
}

// EnqueueVerificationEmail enqueues a verification email job.
func (c *Client) EnqueueVerificationEmail(ctx context.Context, payload VerificationEmailPayload) error {
	task, err := NewVerificationEmailTask(payload)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	info, err := c.client.EnqueueContext(ctx, task)
	if err != nil {
		c.logger.Error("failed to enqueue verification email",
			"email", payload.UserEmail,
			"error", err,
		)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.Info("verification email queued",
		"task_id", info.ID,
		"email", payload.UserEmail,
		"queue", info.Queue,
	)
	return nil
}

// EnqueuePasswordReset enqueues a password reset email job.
func (c *Client) EnqueuePasswordReset(ctx context.Context, payload PasswordResetPayload) error {
	task, err := NewPasswordResetTask(payload)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	info, err := c.client.EnqueueContext(ctx, task)
	if err != nil {
		c.logger.Error("failed to enqueue password reset email",
			"email", payload.UserEmail,
			"error", err,
		)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.Info("password reset email queued",
		"task_id", info.ID,
		"email", payload.UserEmail,
		"queue", info.Queue,
	)
	return nil
}

// EnqueueAITriage enqueues an AI triage job with optional delay.
func (c *Client) EnqueueAITriage(ctx context.Context, payload AITriagePayload, delay time.Duration) error {
	task, err := NewAITriageTask(payload, delay)
	if err != nil {
		return fmt.Errorf("failed to create task: %w", err)
	}

	info, err := c.client.EnqueueContext(ctx, task)
	if err != nil {
		c.logger.Error("failed to enqueue AI triage",
			"result_id", payload.ResultID,
			"finding_id", payload.FindingID,
			"error", err,
		)
		return fmt.Errorf("failed to enqueue task: %w", err)
	}

	c.logger.Info("AI triage queued",
		"task_id", info.ID,
		"result_id", payload.ResultID,
		"finding_id", payload.FindingID,
		"queue", info.Queue,
		"delay", delay,
	)
	return nil
}
