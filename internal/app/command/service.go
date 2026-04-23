package command

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// Service handles command-related business operations.
type Service struct {
	repo   commanddom.Repository
	logger *logger.Logger
}

// NewService creates a new Service.
func NewService(repo commanddom.Repository, log *logger.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: log.With("service", "command"),
	}
}

// CreateInput represents the input for creating a command.
type CreateInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	AgentID   string          `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Type      string          `json:"type" validate:"required,oneof=scan collect health_check config_update cancel"`
	Priority  string          `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresIn int             `json:"expires_in,omitempty"` // Seconds until expiration
}

// Create creates a new command.
func (s *Service) Create(ctx context.Context, input CreateInput) (*commanddom.Command, error) {
	s.logger.Info("creating command", "type", input.Type, "priority", input.Priority)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cmdType := commanddom.CommandType(input.Type)
	priority := commanddom.CommandPriority(input.Priority)
	if priority == "" {
		priority = commanddom.CommandPriorityNormal
	}

	cmd, err := commanddom.NewCommand(tenantID, cmdType, priority, input.Payload)
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

// Get retrieves a command by ID.
func (s *Service) Get(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
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

// ListInput represents the input for listing commands.
type ListInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	AgentID  string `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Type     string `json:"type" validate:"omitempty,oneof=scan collect health_check config_update cancel"`
	Status   string `json:"status" validate:"omitempty,oneof=pending acknowledged running completed failed canceled expired"`
	Priority string `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
}

// List lists commands with filters.
func (s *Service) List(ctx context.Context, input ListInput) (pagination.Result[*commanddom.Command], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*commanddom.Command]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := commanddom.Filter{
		TenantID: &tenantID,
	}

	if input.AgentID != "" {
		agentID, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return pagination.Result[*commanddom.Command]{}, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		filter.AgentID = &agentID
	}

	if input.Type != "" {
		t := commanddom.CommandType(input.Type)
		filter.Type = &t
	}

	if input.Status != "" {
		st := commanddom.CommandStatus(input.Status)
		filter.Status = &st
	}

	if input.Priority != "" {
		p := commanddom.CommandPriority(input.Priority)
		filter.Priority = &p
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// PollInput represents the input for polling commands.
type PollInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	AgentID  string `json:"agent_id,omitempty" validate:"omitempty,uuid"`
	Limit    int    `json:"limit" validate:"min=1,max=100"`
}

// Poll retrieves pending commands for an agent.
func (s *Service) Poll(ctx context.Context, input PollInput) ([]*commanddom.Command, error) {
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

// Acknowledge marks a command as acknowledged.
func (s *Service) Acknowledge(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
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

// Start marks a command as running.
func (s *Service) Start(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status != commanddom.CommandStatusAcknowledged {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be acknowledged before starting", shared.ErrValidation)
	}

	cmd.Start()
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// CompleteInput represents the input for completing a command.
type CompleteInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	CommandID string          `json:"command_id" validate:"required,uuid"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// Complete marks a command as completed.
func (s *Service) Complete(ctx context.Context, input CompleteInput) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, input.TenantID, input.CommandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status != commanddom.CommandStatusRunning {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be running to complete", shared.ErrValidation)
	}

	cmd.Complete(input.Result)
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// FailInput represents the input for failing a command.
type FailInput struct {
	TenantID     string `json:"tenant_id" validate:"required,uuid"`
	CommandID    string `json:"command_id" validate:"required,uuid"`
	ErrorMessage string `json:"error_message"`
}

// Fail marks a command as failed.
func (s *Service) Fail(ctx context.Context, input FailInput) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, input.TenantID, input.CommandID)
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
func (s *Service) CancelCommand(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	if cmd.Status == commanddom.CommandStatusCompleted {
		return nil, shared.NewDomainError("INVALID_STATE", "cannot cancel completed command", shared.ErrValidation)
	}

	cmd.Cancel()
	if err := s.repo.Update(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// DeleteCommand deletes a command.
func (s *Service) DeleteCommand(ctx context.Context, tenantID, commandID string) error {
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
func (s *Service) ExpireOldCommands(ctx context.Context) (int64, error) {
	return s.repo.ExpireOldCommands(ctx)
}
