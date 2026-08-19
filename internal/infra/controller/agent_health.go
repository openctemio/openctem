package controller

import (
	"context"
	"time"

	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// agentAuditSystemActor is the actor recorded on agent lifecycle audit events
// emitted by this background controller (no user request behind them). LogEvent
// treats an empty ActorID + non-empty email as a system action.
const agentAuditSystemActor = "system"

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
	agentRepo    agent.Repository
	auditService *auditapp.AuditService
	config       *AgentHealthControllerConfig
	logger       *logger.Logger
}

// NewAgentHealthController creates a new AgentHealthController.
//
// auditService is optional (nil-safe): when provided, each agent that
// transitions to offline is recorded as an agent.disconnected event in the
// tamper-evident audit_logs so the Agent detail UI can show lifecycle history.
func NewAgentHealthController(
	agentRepo agent.Repository,
	auditService *auditapp.AuditService,
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
		agentRepo:    agentRepo,
		auditService: auditService,
		config:       config,
		logger:       config.Logger,
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
			c.auditDisconnect(ctx, agentID)
		}
	}

	return len(offlineAgentIDs), nil
}

// auditDisconnect records an agent.disconnected event for a single agent that
// this tick transitioned to offline. MarkStaleAgentsOffline only returns agents
// whose health WAS online (its WHERE clause), so this is a genuine online->offline
// transition — repeated reconciles never re-emit for an already-offline agent.
//
// Tenant agents only: platform agents (TenantID == nil) are shared infrastructure
// with no owning tenant to scope the audit log to. Best-effort — a failure to
// resolve or log must not abort the reconcile.
func (c *AgentHealthController) auditDisconnect(ctx context.Context, agentID shared.ID) {
	if c.auditService == nil {
		return
	}

	a, err := c.agentRepo.GetByID(ctx, agentID)
	if err != nil {
		c.logger.Warn("could not load agent for disconnect audit",
			"controller", "agent-health",
			"agent_id", agentID,
			"error", err,
		)
		return
	}
	if a.TenantID == nil {
		return // platform agent — no tenant to scope the audit event to
	}

	_ = c.auditService.LogAgentDisconnected(ctx, auditapp.AuditContext{
		TenantID:   a.TenantID.String(),
		ActorEmail: agentAuditSystemActor,
	}, a.ID.String(), a.Name)
}
