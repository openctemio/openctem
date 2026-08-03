package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	agentdom "github.com/openctemio/api/pkg/domain/agent"
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

// metricsFreshness bounds how old an agent's resource metrics may be before
// the selector stops trusting them. A crashed or wedged agent keeps its last
// reported CPU/memory forever; without this guard one bad sample would
// permanently bias scheduling away from (or towards) that agent. Agents
// heartbeat far more often than this, so fresh agents are unaffected.
const metricsFreshness = 5 * time.Minute

// AgentSelector handles intelligent agent selection for job execution.
type AgentSelector struct {
	agentRepo   agentdom.Repository
	commandRepo command.Repository
	agentState  *redis.AgentStateStore
	logger      *logger.Logger

	// weights drive selectLeastLoaded's scoring. Defaults to the compiled-in
	// weight set; SetLoadBalancingWeights installs the operator-configured
	// AGENT_LB_* values at boot.
	weights agentdom.LoadBalancingWeights
}

// NewAgentSelector creates a new AgentSelector.
func NewAgentSelector(
	agentRepo agentdom.Repository,
	commandRepo command.Repository,
	agentState *redis.AgentStateStore,
	log *logger.Logger,
) *AgentSelector {
	return &AgentSelector{
		agentRepo:   agentRepo,
		commandRepo: commandRepo,
		agentState:  agentState,
		logger:      log.With("service", "agent_selector"),
		weights:     agentdom.DefaultLoadBalancingWeights(),
	}
}

// SetLoadBalancingWeights installs the operator-configured load-balancing
// weights (AGENT_LB_*). Call once at boot, before the selector serves traffic.
// An all-zero weight set is ignored — it would score every agent at 0 and make
// selection arbitrary.
func (s *AgentSelector) SetLoadBalancingWeights(w agentdom.LoadBalancingWeights) {
	if w.IsZero() {
		s.logger.Warn("ignoring all-zero agent load-balancing weights; keeping defaults")
		return
	}
	s.weights = w
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
	Agent   *agentdom.Agent
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

// selectLeastLoaded selects the agent with the lowest weighted load score.
//
// The score is the same formula the agent's persisted load_score column uses
// (Agent.ComputeLoadScoreWithWeights), evaluated with the deployment's
// AGENT_LB_* weights. Scoring here rather than reading load_score keeps the
// decision consistent even for rows written before the weights changed.
//
// Agents at or above their concurrency limit are skipped, matching the
// previous behavior (which started at 100% load and required a strict
// improvement). Ties keep the first candidate, so selection stays stable.
func (s *AgentSelector) selectLeastLoaded(agents []*agentdom.Agent) *agentdom.Agent {
	if len(agents) == 0 {
		return nil
	}

	var best *agentdom.Agent
	bestScore := math.MaxFloat64
	now := time.Now()

	for _, a := range agents {
		if a.MaxConcurrentJobs <= 0 {
			// Agent has no limit, assume 0 load
			return a
		}
		if a.CurrentJobs >= a.MaxConcurrentJobs {
			// Fully loaded — never a candidate.
			continue
		}
		score := s.loadScore(a, now)
		if score < bestScore {
			best = a
			bestScore = score
		}
	}

	return best
}

// loadScore returns the weighted load score used for ranking. When the agent
// has no fresh resource metrics only the job-load term contributes, so an
// agent that has never reported CPU/memory is ranked purely on queue depth
// instead of being flattered by zeroed metrics.
func (s *AgentSelector) loadScore(a *agentdom.Agent, now time.Time) float64 {
	if a.MetricsUpdatedAt == nil || now.Sub(*a.MetricsUpdatedAt) > metricsFreshness {
		return s.weights.JobLoad * a.JobLoadPercent()
	}
	return a.ComputeLoadScoreWithWeights(s.weights)
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
