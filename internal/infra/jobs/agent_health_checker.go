package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/logger"
)

// AgentHealthChecker periodically checks for stale agents and marks them as offline (health).
// Note: This updates Health (automatic), not Status (admin-controlled).
// Agents can still authenticate if their Status is 'active', regardless of Health.
type AgentHealthChecker struct {
	agentRepo agent.Repository
	config    *config.AgentConfig
	logger    *logger.Logger
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewAgentHealthChecker creates a new AgentHealthChecker.
func NewAgentHealthChecker(agentRepo agent.Repository, cfg *config.AgentConfig, log *logger.Logger) *AgentHealthChecker {
	return &AgentHealthChecker{
		agentRepo: agentRepo,
		config:    cfg,
		logger:    log.With("component", "agent-health-checker"),
		stopCh:    make(chan struct{}),
	}
}

// Start starts the health checker in a background goroutine.
func (c *AgentHealthChecker) Start() {
	if !c.config.Enabled {
		c.logger.Info("agent health checker is disabled")
		return
	}

	c.logger.Info("starting agent health checker",
		"heartbeat_timeout", c.config.HeartbeatTimeout,
		"check_interval", c.config.HealthCheckInterval,
	)

	c.wg.Add(1)
	go c.run()
}

// Stop stops the health checker gracefully.
func (c *AgentHealthChecker) Stop() {
	c.logger.Info("stopping agent health checker")
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("agent health checker stopped")
}

func (c *AgentHealthChecker) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	c.checkStaleAgents()

	for {
		select {
		case <-ticker.C:
			c.checkStaleAgents()
		case <-c.stopCh:
			return
		}
	}
}

func (c *AgentHealthChecker) checkStaleAgents() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	count, err := c.agentRepo.MarkStaleAsOffline(ctx, c.config.HeartbeatTimeout)
	if err != nil {
		c.logger.Error("failed to mark stale agents as offline", "error", err)
		return
	}

	if count > 0 {
		c.logger.Info("marked stale agents as offline (health)",
			"count", count,
			"timeout", c.config.HeartbeatTimeout,
		)
	}
}
