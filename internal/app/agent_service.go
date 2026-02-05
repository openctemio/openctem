package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AgentService handles agent-related business operations.
type AgentService struct {
	repo         agent.Repository
	auditService *AuditService
	logger       *logger.Logger
}

// NewAgentService creates a new AgentService.
func NewAgentService(repo agent.Repository, auditService *AuditService, log *logger.Logger) *AgentService {
	return &AgentService{
		repo:         repo,
		auditService: auditService,
		logger:       log.With("service", "agent"),
	}
}

// CreateAgentInput represents the input for creating an agent.
type CreateAgentInput struct {
	TenantID          string   `json:"tenant_id" validate:"required,uuid"`
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Type              string   `json:"type" validate:"required,oneof=runner worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	ExecutionMode     string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
	// Audit context (optional, for audit logging)
	AuditContext *AuditContext `json:"-"`
}

// CreateAgentOutput represents the output after creating an agent.
type CreateAgentOutput struct {
	Agent  *agent.Agent `json:"agent"`
	APIKey string       `json:"api_key"` // Only returned on creation
}

// CreateAgent creates a new agent and generates an API key.
func (s *AgentService) CreateAgent(ctx context.Context, input CreateAgentInput) (*CreateAgentOutput, error) {
	s.logger.Info("creating agent", "name", input.Name, "type", input.Type)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	agentType := agent.AgentType(input.Type)
	executionMode := agent.ExecutionMode(input.ExecutionMode)
	if executionMode == "" {
		executionMode = agentType.DefaultExecutionMode()
	}

	a, err := agent.NewAgent(tenantID, input.Name, agentType, input.Description, input.Capabilities, input.Tools, executionMode)
	if err != nil {
		return nil, err
	}

	// Set max concurrent jobs if provided
	if input.MaxConcurrentJobs > 0 {
		a.SetMaxConcurrentJobs(input.MaxConcurrentJobs)
	}

	// Generate API key
	apiKey, hash, prefix, err := generateAgentAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}
	a.SetAPIKey(hash, prefix)

	if err := s.repo.Create(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && input.AuditContext != nil {
		_ = s.auditService.LogAgentCreated(ctx, *input.AuditContext, a.ID.String(), a.Name, string(a.Type))
	}

	return &CreateAgentOutput{
		Agent:  a,
		APIKey: apiKey,
	}, nil
}

// GetAgent retrieves an agent by ID.
func (s *AgentService) GetAgent(ctx context.Context, tenantID, agentID string) (*agent.Agent, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	aid, err := shared.IDFromString(agentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, aid)
}

// ListAgentsInput represents the input for listing agents.
type ListAgentsInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	Type          string   `json:"type" validate:"omitempty,oneof=runner worker collector sensor"`
	Status        string   `json:"status" validate:"omitempty,oneof=active disabled revoked"`      // Admin-controlled
	Health        string   `json:"health" validate:"omitempty,oneof=unknown online offline error"` // Automatic
	ExecutionMode string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	Search        string   `json:"search" validate:"max=255"`
	HasCapacity   *bool    `json:"has_capacity"` // Filter by agents with available capacity
	Page          int      `json:"page"`
	PerPage       int      `json:"per_page"`
}

// ListAgents lists agents with filters.
func (s *AgentService) ListAgents(ctx context.Context, input ListAgentsInput) (pagination.Result[*agent.Agent], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*agent.Agent]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := agent.Filter{
		TenantID:     &tenantID,
		Capabilities: input.Capabilities,
		Tools:        input.Tools,
		Search:       input.Search,
		HasCapacity:  input.HasCapacity,
	}

	if input.Type != "" {
		t := agent.AgentType(input.Type)
		filter.Type = &t
	}

	if input.Status != "" {
		st := agent.AgentStatus(input.Status)
		filter.Status = &st
	}

	if input.ExecutionMode != "" {
		em := agent.ExecutionMode(input.ExecutionMode)
		filter.ExecutionMode = &em
	}

	if input.Health != "" {
		h := agent.AgentHealth(input.Health)
		filter.Health = &h
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// UpdateAgentInput represents the input for updating an agent.
type UpdateAgentInput struct {
	TenantID          string   `json:"tenant_id" validate:"required,uuid"`
	AgentID           string   `json:"agent_id" validate:"required,uuid"`
	Name              string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	Status            string   `json:"status" validate:"omitempty,oneof=active disabled revoked"` // Admin-controlled
	MaxConcurrentJobs *int     `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
	// Audit context (optional, for audit logging)
	AuditContext *AuditContext `json:"-"`
}

// UpdateAgent updates an agent.
func (s *AgentService) UpdateAgent(ctx context.Context, input UpdateAgentInput) (*agent.Agent, error) {
	a, err := s.GetAgent(ctx, input.TenantID, input.AgentID)
	if err != nil {
		return nil, err
	}

	// Track changes for audit
	changes := audit.NewChanges()
	oldName := a.Name

	if input.Name != "" && input.Name != a.Name {
		changes.Set("name", a.Name, input.Name)
		a.Name = input.Name
	}

	if input.Description != "" && input.Description != a.Description {
		changes.Set("description", a.Description, input.Description)
		a.Description = input.Description
	}

	if len(input.Capabilities) > 0 {
		a.Capabilities = input.Capabilities
	}

	if len(input.Tools) > 0 {
		a.Tools = input.Tools
	}

	if input.Status != "" {
		oldStatus := string(a.Status)
		a.SetStatus(agent.AgentStatus(input.Status), "")
		changes.Set("status", oldStatus, input.Status)
	}

	if input.MaxConcurrentJobs != nil {
		changes.Set("max_concurrent_jobs", a.MaxConcurrentJobs, *input.MaxConcurrentJobs)
		a.SetMaxConcurrentJobs(*input.MaxConcurrentJobs)
	}

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && input.AuditContext != nil && !changes.IsEmpty() {
		agentName := a.Name
		if agentName == "" {
			agentName = oldName
		}
		_ = s.auditService.LogAgentUpdated(ctx, *input.AuditContext, a.ID.String(), agentName, changes)
	}

	return a, nil
}

// AgentHeartbeatData represents the data received from agent heartbeat.
type AgentHeartbeatData struct {
	Version       string
	Hostname      string
	CPUPercent    float64
	MemoryPercent float64
	CurrentJobs   int
	Region        string
}

// UpdateHeartbeat updates agent metrics from heartbeat.
func (s *AgentService) UpdateHeartbeat(ctx context.Context, agentID shared.ID, data AgentHeartbeatData) error {
	a, err := s.repo.GetByID(ctx, agentID)
	if err != nil {
		return err
	}

	// Update runtime info
	if data.Version != "" || data.Hostname != "" {
		a.UpdateRuntimeInfo(data.Version, data.Hostname, nil)
	}

	// Update metrics
	a.UpdateMetrics(data.CPUPercent, data.MemoryPercent, data.CurrentJobs, data.Region)

	// Update last seen and health
	a.UpdateLastSeen()

	return s.repo.Update(ctx, a)
}

// DeleteAgent deletes an agent.
func (s *AgentService) DeleteAgent(ctx context.Context, tenantID, agentID string, auditCtx *AuditContext) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	aid, err := shared.IDFromString(agentID)
	if err != nil {
		return fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
	}

	// Verify agent belongs to tenant and get agent info for audit
	a, err := s.repo.GetByTenantAndID(ctx, tid, aid)
	if err != nil {
		return err
	}

	agentName := a.Name

	if err := s.repo.Delete(ctx, aid); err != nil {
		return err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogAgentDeleted(ctx, *auditCtx, agentID, agentName)
	}

	return nil
}

// RegenerateAPIKey generates a new API key for an agent.
func (s *AgentService) RegenerateAPIKey(ctx context.Context, tenantID, agentID string, auditCtx *AuditContext) (string, error) {
	a, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return "", err
	}

	apiKey, hash, prefix, err := generateAgentAPIKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	a.SetAPIKey(hash, prefix)
	if err := s.repo.Update(ctx, a); err != nil {
		return "", err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogAgentKeyRegenerated(ctx, *auditCtx, agentID, a.Name)
	}

	return apiKey, nil
}

// AuthenticateByAPIKey authenticates an agent by API key.
// Authentication is based on admin-controlled Status field only:
// - Active: allowed to authenticate
// - Disabled: admin has disabled the agent
// - Revoked: access permanently revoked
// The Health field (unknown/online/offline/error) is for monitoring only.
func (s *AgentService) AuthenticateByAPIKey(ctx context.Context, apiKey string) (*agent.Agent, error) {
	hash := hashAgentAPIKey(apiKey)
	a, err := s.repo.GetByAPIKeyHash(ctx, hash)
	if err != nil {
		return nil, shared.NewDomainError("UNAUTHORIZED", "invalid API key", shared.ErrUnauthorized)
	}

	// Check admin-controlled status (not health)
	if !a.Status.CanAuthenticate() {
		if a.Status == agent.AgentStatusRevoked {
			return nil, shared.NewDomainError("FORBIDDEN", "agent access has been revoked", shared.ErrForbidden)
		}
		return nil, shared.NewDomainError("FORBIDDEN", "agent is disabled", shared.ErrForbidden)
	}

	// Update last seen and health (async)
	go func() {
		_ = s.repo.UpdateLastSeen(context.Background(), a.ID)
	}()

	return a, nil
}

// ActivateAgent activates an agent (admin action).
func (s *AgentService) ActivateAgent(ctx context.Context, tenantID, agentID string, auditCtx *AuditContext) (*agent.Agent, error) {
	a, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}

	if a.Status == agent.AgentStatusRevoked {
		return nil, shared.NewDomainError("FORBIDDEN", "cannot activate revoked agent", shared.ErrForbidden)
	}

	a.Activate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogAgentActivated(ctx, *auditCtx, agentID, a.Name)
	}

	s.logger.Info("agent activated", "agent_id", agentID)
	return a, nil
}

// DisableAgent disables an agent (admin action).
func (s *AgentService) DisableAgent(ctx context.Context, tenantID, agentID, reason string, auditCtx *AuditContext) (*agent.Agent, error) {
	a, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}

	if reason == "" {
		reason = "Disabled by administrator"
	}
	a.Disable(reason)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogAgentDeactivated(ctx, *auditCtx, agentID, a.Name, reason)
	}

	s.logger.Info("agent disabled", "agent_id", agentID, "reason", reason)
	return a, nil
}

// RevokeAgent permanently revokes an agent's access (admin action).
func (s *AgentService) RevokeAgent(ctx context.Context, tenantID, agentID, reason string, auditCtx *AuditContext) (*agent.Agent, error) {
	a, err := s.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}

	if reason == "" {
		reason = "Revoked by administrator"
	}
	a.Revoke(reason)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, err
	}

	// Audit logging
	if s.auditService != nil && auditCtx != nil {
		_ = s.auditService.LogAgentRevoked(ctx, *auditCtx, agentID, a.Name, reason)
	}

	s.logger.Info("agent revoked", "agent_id", agentID, "reason", reason)
	return a, nil
}

// AgentHeartbeatInput represents the input for agent heartbeat.
type AgentHeartbeatInput struct {
	AgentID   shared.ID
	Status    string
	Message   string
	Version   string
	Hostname  string
	IPAddress string
}

// Heartbeat updates agent status from heartbeat.
func (s *AgentService) Heartbeat(ctx context.Context, input AgentHeartbeatInput) error {
	a, err := s.repo.GetByID(ctx, input.AgentID)
	if err != nil {
		return err
	}

	a.UpdateLastSeen()

	if input.Version != "" || input.Hostname != "" || input.IPAddress != "" {
		var ip net.IP
		if input.IPAddress != "" {
			ip = net.ParseIP(input.IPAddress)
		}
		a.UpdateRuntimeInfo(input.Version, input.Hostname, ip)
	}

	if input.Message != "" {
		a.StatusMessage = input.Message
	}

	return s.repo.Update(ctx, a)
}

// FindAvailableAgents finds agents that can handle a task.
func (s *AgentService) FindAvailableAgents(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	return s.repo.FindAvailable(ctx, tenantID, capabilities, tool)
}

// FindAvailableWithCapacity finds agents with available job capacity for load balancing.
func (s *AgentService) FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	return s.repo.FindAvailableWithCapacity(ctx, tenantID, capabilities, tool)
}

// ClaimJob claims a job slot on an agent for load balancing.
func (s *AgentService) ClaimJob(ctx context.Context, agentID shared.ID) error {
	return s.repo.ClaimJob(ctx, agentID)
}

// ReleaseJob releases a job slot on an agent.
func (s *AgentService) ReleaseJob(ctx context.Context, agentID shared.ID) error {
	return s.repo.ReleaseJob(ctx, agentID)
}

// IncrementStats increments agent statistics.
func (s *AgentService) IncrementStats(ctx context.Context, agentID shared.ID, findings, scans, errors int64) error {
	return s.repo.IncrementStats(ctx, agentID, findings, scans, errors)
}

// generateAgentAPIKey generates a new API key for an agent.
func generateAgentAPIKey() (key, hash, prefix string, err error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", "", err
	}

	key = "rda_" + hex.EncodeToString(keyBytes) // rda = exploop agent
	hash = hashAgentAPIKey(key)
	prefix = key[:12] // "rda_" + first 8 hex chars

	return key, hash, prefix, nil
}

// hashAgentAPIKey hashes an agent API key.
func hashAgentAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// =============================================================================
// Tenant Available Capabilities
// =============================================================================

// TenantAvailableCapabilitiesOutput represents the output for available capabilities.
type TenantAvailableCapabilitiesOutput struct {
	Capabilities []string `json:"capabilities"` // Unique capability names available to tenant
	TotalAgents  int      `json:"total_agents"` // Total number of online agents
}

// GetAvailableCapabilitiesForTenant returns all capabilities available to a tenant.
// This aggregates capabilities from the tenant's own agents (if status=active and health=online).
func (s *AgentService) GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) (*TenantAvailableCapabilitiesOutput, error) {
	s.logger.Debug("getting available capabilities for tenant", "tenant_id", tenantID)

	capabilities, err := s.repo.GetAvailableCapabilitiesForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get available capabilities: %w", err)
	}

	// Ensure we return empty array instead of nil
	if capabilities == nil {
		capabilities = []string{}
	}

	return &TenantAvailableCapabilitiesOutput{
		Capabilities: capabilities,
		TotalAgents:  len(capabilities), // This is a simplification; could query actual agent count if needed
	}, nil
}

// HasCapability checks if a tenant has access to a specific capability.
func (s *AgentService) HasCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error) {
	return s.repo.HasAgentForCapability(ctx, tenantID, capability)
}
