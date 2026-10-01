package unit

// Sensor-surface hardening tests for the agent service:
//   - a heartbeat racing an admin revoke / key regeneration cannot undo it
//   - admin key regeneration also revokes self-renewed key rows
//   - agent self-renewal is audited

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// copyingAgentRepo wraps the in-memory mock so GetByID returns a private copy
// (as the real postgres repo does) and lets a test inject an "admin action"
// between the service's read and its write.
type copyingAgentRepo struct {
	*agentSvcMockRepo
	beforeWrite func()
}

func (r *copyingAgentRepo) GetByID(ctx context.Context, id shared.ID) (*agent.Agent, error) {
	a, err := r.agentSvcMockRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cp := *a
	return &cp, nil
}

func (r *copyingAgentRepo) UpdateHeartbeat(ctx context.Context, id shared.ID, hb agent.HeartbeatUpdate) (bool, error) {
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	return r.agentSvcMockRepo.UpdateHeartbeat(ctx, id, hb)
}

// A full-row Update would (and, before the fix, did) write back the status and
// key read at the start of the heartbeat. Also wire Update to the hook so the
// test would catch a regression back to the full-row write.
func (r *copyingAgentRepo) Update(ctx context.Context, a *agent.Agent) error {
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	cp := *a
	return r.agentSvcMockRepo.Update(ctx, &cp)
}

func TestUpdateHeartbeat_ConcurrentRevokeStaysRevoked(t *testing.T) {
	base := newAgentSvcMockRepo()
	tenantID := shared.NewID()
	a := base.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	a.SetAPIKey("old-hash", "rda_old0")

	repo := &copyingAgentRepo{agentSvcMockRepo: base}
	// Admin revokes the agent and rotates its key AFTER the heartbeat read.
	repo.beforeWrite = func() {
		base.mu.Lock()
		defer base.mu.Unlock()
		stored := base.agents[a.ID.String()]
		stored.Revoke("compromised")
		stored.SetAPIKey("admin-new-hash", "rda_new0")
	}
	svc := app.NewAgentService(repo, nil, logger.NewNop())

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{
		Version: "9.9.9", CPUPercent: 10,
	}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	stored := base.agents[a.ID.String()]
	if stored.Status != agent.AgentStatusRevoked {
		t.Fatalf("heartbeat undid the admin revoke: status=%q", stored.Status)
	}
	if stored.APIKeyHash != "admin-new-hash" {
		t.Fatalf("heartbeat overwrote the admin-rotated key hash: %q", stored.APIKeyHash)
	}
	if stored.Version == "9.9.9" {
		t.Error("heartbeat metrics must not be written to a revoked agent")
	}
	if base.updateCalls != 0 {
		t.Errorf("heartbeat must not use the full-row Update, got %d calls", base.updateCalls)
	}
}

func TestUpdateHeartbeat_ActiveAgentUpdatesOnlyLivenessColumns(t *testing.T) {
	base := newAgentSvcMockRepo()
	tenantID := shared.NewID()
	a := base.seedAgent(tenantID, "agent-1", agent.AgentTypeRunner)
	a.SetAPIKey("keep-hash", "rda_keep")
	a.Health = agent.AgentHealthOffline

	repo := &copyingAgentRepo{agentSvcMockRepo: base}
	svc := app.NewAgentService(repo, nil, logger.NewNop())

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{
		Version: "1.2.3", Hostname: "h1", CPUPercent: 50, MemoryPercent: 20,
	}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	stored := base.agents[a.ID.String()]
	if stored.Version != "1.2.3" || stored.Hostname != "h1" || stored.CPUPercent != 50 {
		t.Errorf("heartbeat fields not persisted: %+v", stored)
	}
	if stored.Health != agent.AgentHealthOnline || stored.LastSeenAt == nil {
		t.Error("expected agent online with last_seen set")
	}
	if stored.LoadScore == 0 {
		t.Error("expected load score recomputed from metrics")
	}
	if stored.APIKeyHash != "keep-hash" || stored.Status != agent.AgentStatusActive {
		t.Error("heartbeat must not touch key/status")
	}
	if base.updateHeartbeatCalls != 1 || base.updateCalls != 0 {
		t.Errorf("expected exactly one targeted heartbeat write, got heartbeat=%d full=%d",
			base.updateHeartbeatCalls, base.updateCalls)
	}
}

// A revoked agent's heartbeat (e.g. the request authenticated just before the
// revoke) records no connect event.
func TestUpdateHeartbeat_RevokedAgentNoConnectAudit(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())
	a := repo.seedAgent(shared.NewID(), "agent-1", agent.AgentTypeWorker)
	a.Health = agent.AgentHealthOffline
	a.Revoke("gone")

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, app.AgentHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Errorf("expected no connect audit for a revoked agent, got %d", auditRepo.createCalls)
	}
}

// Renewal must not revive an agent revoked between its status re-read and the
// key write (the targeted UPDATE is status-guarded).
func TestRenewAPIKey_RevokedDuringRenewIsRejected(t *testing.T) {
	base := newAgentSvcMockRepo()
	a := base.seedAgent(shared.NewID(), "agent-1", agent.AgentTypeRunner)
	a.SetAPIKey("old-hash", "rda_old0")

	repo := &revokeOnKeyWriteRepo{agentSvcMockRepo: base}
	svc := app.NewAgentService(repo, nil, logger.NewNop())

	if _, _, err := svc.RenewAPIKey(context.Background(), a); err == nil {
		t.Fatal("expected renewal to fail for an agent revoked mid-renewal")
	}
	stored := base.agents[a.ID.String()]
	if stored.Status != agent.AgentStatusRevoked {
		t.Fatalf("renewal revived a revoked agent: %q", stored.Status)
	}
	if stored.APIKeyHash != "old-hash" {
		t.Fatal("renewal installed a fresh key on a revoked agent")
	}
}

type revokeOnKeyWriteRepo struct{ *agentSvcMockRepo }

func (r *revokeOnKeyWriteRepo) GetByID(ctx context.Context, id shared.ID) (*agent.Agent, error) {
	a, err := r.agentSvcMockRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cp := *a
	return &cp, nil
}

func (r *revokeOnKeyWriteRepo) UpdateAPIKey(ctx context.Context, id shared.ID, hash, prefix string, exp *time.Time, requireActive bool) (bool, error) {
	r.mu.Lock()
	r.agents[id.String()].Revoke("admin")
	r.mu.Unlock()
	return r.agentSvcMockRepo.UpdateAPIKey(ctx, id, hash, prefix, exp, requireActive)
}

// Admin regeneration revokes every self-renewed key row, so a renewed copy of a
// leaked credential stops working.
func TestRegenerateAPIKey_RevokesRenewedKeyRows(t *testing.T) {
	repo := newAgentSvcMockRepo()
	keyRepo := newMockAgentAPIKeyRepo()
	svc := newAgentSvcTestService(repo)
	svc.SetKeyTTL(time.Hour)
	svc.SetAPIKeyRepository(keyRepo)
	tenantID := shared.NewID()

	out, err := svc.CreateAgent(context.Background(), app.CreateAgentInput{
		TenantID: tenantID.String(), Name: "regen-agent", Type: "runner",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	renewed, _, err := svc.RenewAPIKey(context.Background(), out.Agent)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), renewed); err != nil {
		t.Fatalf("renewed key should authenticate before regeneration: %v", err)
	}

	regenerated, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), out.Agent.ID.String(), nil)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if _, err := svc.AuthenticateByAPIKey(context.Background(), renewed); err == nil {
		t.Fatal("renewed key row survived admin regeneration")
	}
	if n, _ := keyRepo.CountActiveByAgentID(context.Background(), out.Agent.ID); n != 0 {
		t.Errorf("expected 0 active key rows after regeneration, got %d", n)
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), regenerated); err != nil {
		t.Errorf("regenerated key must authenticate: %v", err)
	}
	if repo.updateCalls != 0 {
		t.Errorf("regeneration must use the targeted key write, got %d full-row updates", repo.updateCalls)
	}
}

func TestRenewAPIKey_WritesAuditEvent(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newAgentSvcMockRepo()
	svc := app.NewAgentService(repo, auditSvc, logger.NewNop())
	a := repo.seedAgent(shared.NewID(), "agent-1", agent.AgentTypeRunner)

	if _, _, err := svc.RenewAPIKey(context.Background(), a); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if auditRepo.createCalls != 1 {
		t.Fatalf("expected 1 audit event for renewal, got %d", auditRepo.createCalls)
	}
	if got := auditRepo.lastCreated.Action(); got != auditdom.ActionAgentKeyRenewed {
		t.Errorf("action = %q, want %q", got, auditdom.ActionAgentKeyRenewed)
	}
}
