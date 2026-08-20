package unit

// Tests for the agent connect/disconnect lifecycle audit trail. These prove the
// events that activate the AgentAuditLog UI (which reads resource_type="agent")
// are actually written to the shared audit_logs, and only on real transitions.

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/agent"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// --- CONNECT (heartbeat transition) --------------------------------------

func TestUpdateHeartbeat_LogsConnectOnOfflineToOnlineTransition(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	a.Health = agent.AgentHealthOffline // previously offline

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{Version: "1.0.0"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 connect audit event, got %d", auditRepo.createCalls)
	}
	got := auditRepo.lastCreated
	if got.Action() != auditdom.ActionAgentConnected {
		t.Errorf("action = %q, want %q", got.Action(), auditdom.ActionAgentConnected)
	}
	if got.ResourceType() != auditdom.ResourceTypeAgent {
		t.Errorf("resource_type = %q, want %q (UI reads 'agent')", got.ResourceType(), auditdom.ResourceTypeAgent)
	}
	if got.ResourceID() != a.ID.String() {
		t.Errorf("resource_id = %q, want agent id %q", got.ResourceID(), a.ID.String())
	}
	if got.TenantID() == nil || *got.TenantID() != tenantID {
		t.Errorf("tenant_id = %v, want %s (must use the agent's own tenant)", got.TenantID(), tenantID)
	}
}

func TestUpdateHeartbeat_NoConnectLogOnSteadyStateHeartbeat(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	a.Health = agent.AgentHealthOnline // already online — a normal recurring heartbeat

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{Version: "1.0.0"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 0 {
		t.Fatalf("steady-state heartbeat must not log a connect event; got %d audit writes", auditRepo.createCalls)
	}
}

func TestUpdateHeartbeat_ConnectLogsOnceThenGoesQuiet(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	a.Health = agent.AgentHealthOffline

	// First heartbeat is the transition -> one connect event.
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #1: %v", err)
	}
	// Second and third heartbeats are steady-state -> no further events.
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #2: %v", err)
	}
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #3: %v", err)
	}

	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 connect event across 3 heartbeats, got %d", auditRepo.createCalls)
	}
}

func TestUpdateHeartbeat_NoConnectLogForPlatformAgent(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())

	a := repo.seedAgent(shared.NewID(), "platform-agent", agent.AgentTypeWorker)
	a.TenantID = nil // platform agent — shared infra, no owning tenant
	a.Health = agent.AgentHealthOffline

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 0 {
		t.Fatalf("platform agent (no tenant) must not produce a tenant-scoped connect event; got %d", auditRepo.createCalls)
	}
}

// --- DISCONNECT (health controller mark-offline) --------------------------

func TestAgentHealthReconcile_LogsDisconnectForNewlyOfflineAgent(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()

	tenantID := shared.NewID()
	a := repo.seedAgent(tenantID, "agent-1", agent.AgentTypeWorker)
	// The controller flow: MarkStaleAgentsOffline already flipped health to
	// offline and returns the id; GetByID then resolves tenant + name.
	a.Health = agent.AgentHealthOffline
	repo.staleOfflineIDs = []shared.ID{a.ID}

	ctrl := controller.NewAgentHealthController(repo, auditSvc, &controller.AgentHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	n, err := ctrl.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("Reconcile reported %d offline agents, want 1", n)
	}
	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 disconnect audit event, got %d", auditRepo.createCalls)
	}
	got := auditRepo.lastCreated
	if got.Action() != auditdom.ActionAgentDisconnected {
		t.Errorf("action = %q, want %q", got.Action(), auditdom.ActionAgentDisconnected)
	}
	if got.ResourceType() != auditdom.ResourceTypeAgent {
		t.Errorf("resource_type = %q, want %q", got.ResourceType(), auditdom.ResourceTypeAgent)
	}
	if got.ResourceID() != a.ID.String() {
		t.Errorf("resource_id = %q, want %q", got.ResourceID(), a.ID.String())
	}
	if got.TenantID() == nil || *got.TenantID() != tenantID {
		t.Errorf("tenant_id = %v, want %s", got.TenantID(), tenantID)
	}
}

func TestAgentHealthReconcile_NoDisconnectWhenNothingWentOffline(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	repo.staleOfflineIDs = nil // steady state — no transitions this tick

	ctrl := controller.NewAgentHealthController(repo, auditSvc, &controller.AgentHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Fatalf("no agents went offline; expected 0 audit writes, got %d", auditRepo.createCalls)
	}
}

func TestAgentHealthReconcile_NoDisconnectForPlatformAgent(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()

	a := repo.seedAgent(shared.NewID(), "platform-agent", agent.AgentTypeWorker)
	a.TenantID = nil // platform agent
	a.Health = agent.AgentHealthOffline
	repo.staleOfflineIDs = []shared.ID{a.ID}

	ctrl := controller.NewAgentHealthController(repo, auditSvc, &controller.AgentHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Fatalf("platform agent (no tenant) must not produce a tenant-scoped disconnect event; got %d", auditRepo.createCalls)
	}
}

func TestAgentHealthReconcile_NilAuditServiceIsSafe(t *testing.T) {
	repo := newAgentSvcMockRepo()
	a := repo.seedAgent(shared.NewID(), "agent-1", agent.AgentTypeWorker)
	a.Health = agent.AgentHealthOffline
	repo.staleOfflineIDs = []shared.ID{a.ID}

	// nil audit service — the controller must still reconcile without panicking.
	ctrl := controller.NewAgentHealthController(repo, nil, &controller.AgentHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	n, err := ctrl.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile with nil audit service: %v", err)
	}
	if n != 1 {
		t.Fatalf("Reconcile reported %d, want 1", n)
	}
}
