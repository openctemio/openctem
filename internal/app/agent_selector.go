package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AgentAvailabilityResult represents agent availability status.
type AgentAvailabilityResult struct {
	HasTenantAgent bool
	Available      bool
	Message        string
}

// AgentSelectionMode defines which agents to consider.
type AgentSelectionMode string

const (
	// SelectTenantOnly only considers tenant's own agents.
	SelectTenantOnly AgentSelectionMode = "tenant_only"
	// SelectAny selects from any available agent.
	SelectAny AgentSelectionMode = "any"
)

var (
	// ErrNoAgentAvailable is returned when no suitable agent is found.
	ErrNoAgentAvailable = errors.New("no suitable agent available")
)

// AgentSelector handles intelligent agent selection for job execution.
type AgentSelector struct {
	agentRepo   agent.Repository
	commandRepo command.Repository
	agentState  *redis.AgentStateStore
	logger      *logger.Logger
}

// NewAgentSelector creates a new AgentSelector.
func NewAgentSelector(
	agentRepo agent.Repository,
	commandRepo command.Repository,
	agentState *redis.AgentStateStore,
	log *logger.Logger,
) *AgentSelector {
	return &AgentSelector{
		agentRepo:   agentRepo,
		commandRepo: commandRepo,
		agentState:  agentState,
		logger:      log.With("service", "agent_selector"),
	}
}

// SelectAgentRequest represents a request to select an agent for a job.
type SelectAgentRequest struct {
	TenantID     shared.ID
	Capabilities []string
	Tool         string
	Region       string // Preferred region
	Mode         AgentSelectionMode
	AllowQueue   bool // If true, return queue info instead of error when no agent available
}

// SelectAgentResult represents the result of agent selection.
type SelectAgentResult struct {
	Agent   *agent.Agent
	Queued  bool
	Message string
}

// SelectAgent selects the best agent for a job based on the selection mode.
func (s *AgentSelector) SelectAgent(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error) {
	return s.selectTenantAgent(ctx, req)
}

// selectTenantAgent selects from tenant's own agents.
func (s *AgentSelector) selectTenantAgent(ctx context.Context, req SelectAgentRequest) (*SelectAgentResult, error) {
	// Find available tenant agents with capacity
	agents, err := s.agentRepo.FindAvailableWithCapacity(ctx, req.TenantID, req.Capabilities, req.Tool)
	if err != nil {
		return nil, fmt.Errorf("failed to find tenant agents: %w", err)
	}

	if len(agents) == 0 {
		if req.AllowQueue {
			return &SelectAgentResult{
				Queued:  true,
				Message: "No tenant agent available, job will be queued",
			}, nil
		}
		return nil, ErrNoAgentAvailable
	}

	// Select the best agent (least loaded)
	selected := s.selectLeastLoaded(agents)

	return &SelectAgentResult{
		Agent:   selected,
		Message: "Tenant agent assigned",
	}, nil
}

// selectLeastLoaded selects the agent with the lowest load.
func (s *AgentSelector) selectLeastLoaded(agents []*agent.Agent) *agent.Agent {
	if len(agents) == 0 {
		return nil
	}

	var best *agent.Agent
	bestLoad := float64(1.0) // Start with 100% load

	for _, a := range agents {
		if a.MaxConcurrentJobs <= 0 {
			// Agent has no limit, assume 0 load
			return a
		}
		load := float64(a.CurrentJobs) / float64(a.MaxConcurrentJobs)
		if load < bestLoad {
			best = a
			bestLoad = load
		}
	}

	return best
}

// CheckAgentAvailability checks if any agent is available for the given scan configuration.
// This should be called before creating a scan to ensure execution is possible.
func (s *AgentSelector) CheckAgentAvailability(ctx context.Context, tenantID shared.ID, toolName string, tenantOnly bool) *AgentAvailabilityResult {
	result := &AgentAvailabilityResult{}

	// Check for tenant agents (online and with capacity)
	agents, err := s.agentRepo.FindAvailableWithCapacity(ctx, tenantID, nil, toolName)
	if err == nil && len(agents) > 0 {
		result.HasTenantAgent = true
	}

	// Determine overall availability
	result.Available = result.HasTenantAgent

	// Generate message
	if result.Available {
		result.Message = "Tenant agent available"
	} else {
		result.Message = "No tenant agent available. Deploy an agent to execute scans."
	}

	return result
}
