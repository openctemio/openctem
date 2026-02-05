package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// CommandService handles command-related business operations.
type CommandService struct {
	repo   command.Repository
	logger *logger.Logger
}

// NewCommandService creates a new CommandService.
func NewCommandService(repo command.Repository, log *logger.Logger) *CommandService {
	return &CommandService{
		repo:   repo,
		logger: log.With("service", "command"),
	}
}

// CreateCommandInput represents the input for creating a command.
type CreateCommandInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	AgentID   string          `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Type      string          `json:"type" validate:"required,oneof=scan collect health_check config_update cancel"`
	Priority  string          `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresIn int             `json:"expires_in,omitempty"` // Seconds until expiration
}

// CreateCommand creates a new command.
func (s *CommandService) CreateCommand(ctx context.Context, input CreateCommandInput) (*command.Command, error) {
	s.logger.Info("creating command", "type", input.Type, "priority", input.Priority)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cmdType := command.CommandType(input.Type)
	priority := command.CommandPriority(input.Priority)
	if priority == "" {
		priority = command.CommandPriorityNormal
	}

	cmd, err := command.NewCommand(tenantID, cmdType, priority, input.Payload)
	if err != nil {
		return nil, err
	}

	if input.AgentID != "" {
		agentID, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		cmd.SetAgentID(agentID)
	}

	if input.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(input.ExpiresIn) * time.Second)
		cmd.SetExpiration(expiresAt)
	}

	if err := s.repo.Create(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// GetCommand retrieves a command by ID.
func (s *CommandService) GetCommand(ctx context.Context, tenantID, commandID string) (*command.Command, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(commandID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid command id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, cid)
}

// ListCommandsInput represents the input for listing commands.
type ListCommandsInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	AgentID  string `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Type     string `json:"type" validate:"omitempty,oneof=scan collect health_check config_update cancel"`
	Status   string `json:"status" validate:"omitempty,oneof=pending acknowledged running completed failed canceled expired"`
	Priority string `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
}

// ListCommands lists commands with filters.
func (s *CommandService) ListCommands(ctx context.Context, input ListCommandsInput) (pagination.Result[*command.Command], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*command.Command]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := command.Filter{
		TenantID: &tenantID,
	}

	if input.AgentID != "" {
		agentID, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return pagination.Result[*command.Command]{}, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		filter.AgentID = &agentID
	}

	if input.Type != "" {
		t := command.CommandType(input.Type)
		filter.Type = &t
	}

	if input.Status != "" {
		st := command.CommandStatus(input.Status)
		filter.Status = &st
	}

	if input.Priority != "" {
		p := command.CommandPriority(input.Priority)
		filter.Priority = &p
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// PollCommandsInput represents the input for polling commands.
type PollCommandsInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	AgentID  string `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Limit    int    `json:"limit" validate:"min=1,max=100"`
}

// PollCommands retrieves pending commands for an agent.
func (s *CommandService) PollCommands(ctx context.Context, input PollCommandsInput) ([]*command.Command, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var agentID *shared.ID
	if input.AgentID != "" {
		aid, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		agentID = &aid
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	return s.repo.GetPendingForAgent(ctx, tenantID, agentID, limit)
}

// AcknowledgeCommand marks a command as acknowledged.
func (s *CommandService) AcknowledgeCommand(ctx context.Context, tenantID, commandID string) (*command.Command, error) {
	cmd, err := s.GetCommand(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	if !cmd.CanBeAcknowledged() {
		return nil, shared.NewDomainError("INVALID_STATE", "command cannot be acknowledged", shared.ErrValidation)
	}

	cmd.Acknowledge()
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// StartCommand marks a command as running.
func (s *CommandService) StartCommand(ctx context.Context, tenantID, commandID string) (*command.Command, error) {
	cmd, err := s.GetCommand(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status != command.CommandStatusAcknowledged {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be acknowledged before starting", shared.ErrValidation)
	}

	cmd.Start()
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// CompleteCommandInput represents the input for completing a command.
type CompleteCommandInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	CommandID string          `json:"command_id" validate:"required,uuid"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// CompleteCommand marks a command as completed.
func (s *CommandService) CompleteCommand(ctx context.Context, input CompleteCommandInput) (*command.Command, error) {
	cmd, err := s.GetCommand(ctx, input.TenantID, input.CommandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status != command.CommandStatusRunning {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be running to complete", shared.ErrValidation)
	}

	cmd.Complete(input.Result)
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// FailCommandInput represents the input for failing a command.
type FailCommandInput struct {
	TenantID     string `json:"tenant_id" validate:"required,uuid"`
	CommandID    string `json:"command_id" validate:"required,uuid"`
	ErrorMessage string `json:"error_message"`
}

// FailCommand marks a command as failed.
func (s *CommandService) FailCommand(ctx context.Context, input FailCommandInput) (*command.Command, error) {
	cmd, err := s.GetCommand(ctx, input.TenantID, input.CommandID)
	if err != nil {
		return nil, err
	}

	cmd.Fail(input.ErrorMessage)
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// CancelCommand marks a command as canceled.
func (s *CommandService) CancelCommand(ctx context.Context, tenantID, commandID string) (*command.Command, error) {
	cmd, err := s.GetCommand(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status == command.CommandStatusCompleted {
		return nil, shared.NewDomainError("INVALID_STATE", "cannot cancel completed command", shared.ErrValidation)
	}

	cmd.Cancel()
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// DeleteCommand deletes a command.
func (s *CommandService) DeleteCommand(ctx context.Context, tenantID, commandID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(commandID)
	if err != nil {
		return fmt.Errorf("%w: invalid command id", shared.ErrValidation)
	}

	// Verify command belongs to tenant
	if _, err := s.repo.GetByTenantAndID(ctx, tid, cid); err != nil {
		return err
	}

	return s.repo.Delete(ctx, cid)
}

// ExpireOldCommands expires old pending commands.
func (s *CommandService) ExpireOldCommands(ctx context.Context) (int64, error) {
	return s.repo.ExpireOldCommands(ctx)
}
