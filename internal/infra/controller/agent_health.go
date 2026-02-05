package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/logger"
)

// AgentHealthControllerConfig configures the AgentHealthController.
type AgentHealthControllerConfig struct {
	// Interval is how often to run the health check.
	// Default: 30 seconds.
	Interval time.Duration

	// StaleTimeout is how long since last heartbeat before marking an agent as offline.
	// Default: 90 seconds (1.5x the typical heartbeat interval of 60s).
	StaleTimeout time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// AgentHealthController periodically checks agent health and marks stale agents as offline.
// This is a K8s-style controller that reconciles the desired state (agents with recent
// heartbeats are online, agents without recent heartbeats are offline) with the actual state.
type AgentHealthController struct {
	agentRepo agent.Repository
	config    *AgentHealthControllerConfig
	logger    *logger.Logger
}

// NewAgentHealthController creates a new AgentHealthController.
func NewAgentHealthController(
	agentRepo agent.Repository,
	config *AgentHealthControllerConfig,
) *AgentHealthController {
	if config == nil {
		config = &AgentHealthControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 30 * time.Second
	}
	if config.StaleTimeout == 0 {
		config.StaleTimeout = 90 * time.Second
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &AgentHealthController{
		agentRepo: agentRepo,
		config:    config,
		logger:    config.Logger,
	}
}

// Name returns the controller name.
func (c *AgentHealthController) Name() string {
	return "agent-health"
}

// Interval returns the reconciliation interval.
func (c *AgentHealthController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile checks agent health and marks stale agents as offline.
// Uses the MarkStaleAgentsOffline method which also updates last_offline_at timestamp.
func (c *AgentHealthController) Reconcile(ctx context.Context) (int, error) {
	// Mark stale agents as offline (based on last_seen_at)
	// This also updates last_offline_at timestamp for historical queries
	offlineAgentIDs, err := c.agentRepo.MarkStaleAgentsOffline(ctx, c.config.StaleTimeout)
	if err != nil {
		c.logger.Error("failed to mark stale agents as offline",
			"controller", "agent-health",
			"error", err,
		)
		return 0, err
	}

	if len(offlineAgentIDs) > 0 {
		c.logger.Info("marked stale agents as offline",
			"controller", "agent-health",
			"count", len(offlineAgentIDs),
			"stale_timeout", c.config.StaleTimeout,
		)
		for _, agentID := range offlineAgentIDs {
			c.logger.Debug("agent marked offline due to heartbeat timeout",
				"controller", "agent-health",
				"agent_id", agentID,
				"stale_timeout", c.config.StaleTimeout,
			)
		}
	}

	return len(offlineAgentIDs), nil
}
