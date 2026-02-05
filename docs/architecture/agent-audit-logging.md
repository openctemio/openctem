# Agent Audit Logging Architecture

## Overview

This document describes the comprehensive audit logging architecture for Platform Agents. The goal is to provide complete visibility into all agent lifecycle events, security-sensitive operations, and operational activities for compliance, debugging, and security monitoring.

**Core Principle**: "Log state changes and errors only - NOT every heartbeat"

> ⚠️ **QUAN TRỌNG**: Audit log chỉ dùng cho state changes và errors, KHÔNG log mỗi heartbeat.
> Xem [Agent Heartbeat Optimization](./agent-heartbeat-optimization.md) để hiểu tại sao.

## Problem Statement

### Current Issues

1. **Missing Audit Logs**: Critical agent operations have NO audit logging:
   - Agent registration via bootstrap token
   - Agent heartbeat (first connection/disconnection)
   - Agent enable/disable operations
   - Agent deletion
   - Bootstrap token creation/revocation

2. **Unused Methods**: Audit service methods exist but are NEVER called:
   - `LogAgentConnected()` - defined in audit_service.go:665-671
   - `LogAgentDisconnected()` - defined in audit_service.go:674-679

3. **No Integration**: `platform_agent_service.go` has ZERO audit logging calls despite handling security-critical operations

4. **Compliance Gap**: Cannot answer audit questions like:
   - "When was this agent last connected?"
   - "Who disabled this agent and why?"
   - "Which bootstrap token was used to register this agent?"

### Existing Infrastructure

The audit system infrastructure is mature and production-ready:

| Component | Status | Location |
|-----------|--------|----------|
| Domain Model | ✅ Complete | `domain/audit/value_objects.go` |
| Repository | ✅ Complete | `infra/postgres/audit_repository.go` |
| Service Layer | ✅ Complete | `app/audit_service.go` |
| Agent Actions | ✅ Defined | 9 actions in value_objects.go (lines 96-104) |
| Convenience Methods | ⚠️ Partial | Some exist but not called |

### Defined Agent Audit Actions

```go
// Currently defined in domain/audit/value_objects.go:96-104
ActionAgentCreated        Action = "agent.created"
ActionAgentUpdated        Action = "agent.updated"
ActionAgentDeleted        Action = "agent.deleted"
ActionAgentActivated      Action = "agent.activated"
ActionAgentDeactivated    Action = "agent.deactivated"
ActionAgentRevoked        Action = "agent.revoked"
ActionAgentKeyRegenerated Action = "agent.key_regenerated"
ActionAgentConnected      Action = "agent.connected"
ActionAgentDisconnected   Action = "agent.disconnected"
```

## Architecture Design

### New Audit Actions Required

```go
// Add to domain/audit/value_objects.go
const (
    // Platform Agent Actions
    ActionAgentRegistered          Action = "agent.registered"          // Self-registration via bootstrap
    ActionAgentHeartbeatStarted    Action = "agent.heartbeat_started"   // First heartbeat (came online)
    ActionAgentHeartbeatTimeout    Action = "agent.heartbeat_timeout"   // Heartbeat timeout (went offline)
    ActionAgentCapabilityDrift     Action = "agent.capability_drift"    // Capability mismatch detected
    ActionAgentCapabilityVerified  Action = "agent.capability_verified" // Capabilities verified

    // Bootstrap Token Actions
    ActionBootstrapTokenCreated    Action = "bootstrap_token.created"
    ActionBootstrapTokenRevoked    Action = "bootstrap_token.revoked"
    ActionBootstrapTokenUsed       Action = "bootstrap_token.used"
    ActionBootstrapTokenExpired    Action = "bootstrap_token.expired"
    ActionBootstrapTokenExhausted  Action = "bootstrap_token.exhausted"
)

// Resource types to add
const (
    ResourceTypeBootstrapToken ResourceType = "bootstrap_token"
    ResourceTypeRegistration   ResourceType = "agent_registration"
)
```

### Audit Service Extensions

```go
// Add to app/audit_service.go

// ============================================
// PLATFORM AGENT AUDIT EVENTS
// ============================================

// LogAgentRegistered logs when an agent self-registers via bootstrap token.
func (s *AuditService) LogAgentRegistered(
    ctx context.Context,
    actx AuditContext,
    agentID, agentName, tokenPrefix, region string,
    capabilities, tools []string,
) error {
    event := NewSuccessEvent(audit.ActionAgentRegistered, audit.ResourceTypeAgent, agentID).
        WithResourceName(agentName).
        WithSeverity(audit.SeverityMedium).
        WithMessage(fmt.Sprintf("Agent '%s' registered via bootstrap token %s", agentName, tokenPrefix)).
        WithMetadata("bootstrap_token_prefix", tokenPrefix).
        WithMetadata("region", region).
        WithMetadata("capabilities", capabilities).
        WithMetadata("tools", tools)
    return s.LogEvent(ctx, actx, event)
}

// LogAgentHeartbeatStarted logs when an agent sends its first heartbeat (comes online).
func (s *AuditService) LogAgentHeartbeatStarted(
    ctx context.Context,
    actx AuditContext,
    agentID, agentName, ipAddress, version string,
) error {
    event := NewSuccessEvent(audit.ActionAgentHeartbeatStarted, audit.ResourceTypeAgent, agentID).
        WithResourceName(agentName).
        WithMessage(fmt.Sprintf("Agent '%s' came online from %s (v%s)", agentName, ipAddress, version)).
        WithMetadata("ip_address", ipAddress).
        WithMetadata("version", version)
    return s.LogEvent(ctx, actx, event)
}

// LogAgentHeartbeatTimeout logs when an agent stops sending heartbeats (goes offline).
func (s *AuditService) LogAgentHeartbeatTimeout(
    ctx context.Context,
    actx AuditContext,
    agentID, agentName string,
    lastSeen time.Time,
) error {
    event := NewSuccessEvent(audit.ActionAgentHeartbeatTimeout, audit.ResourceTypeAgent, agentID).
        WithResourceName(agentName).
        WithSeverity(audit.SeverityMedium).
        WithMessage(fmt.Sprintf("Agent '%s' went offline (last seen: %s)", agentName, lastSeen.Format(time.RFC3339))).
        WithMetadata("last_seen", lastSeen)
    return s.LogEvent(ctx, actx, event)
}

// LogAgentCapabilityDrift logs when agent's reported capabilities don't match declared.
func (s *AuditService) LogAgentCapabilityDrift(
    ctx context.Context,
    actx AuditContext,
    agentID, agentName string,
    missing, excess []string,
) error {
    event := NewSuccessEvent(audit.ActionAgentCapabilityDrift, audit.ResourceTypeAgent, agentID).
        WithResourceName(agentName).
        WithSeverity(audit.SeverityHigh).
        WithMessage(fmt.Sprintf("Capability drift detected for agent '%s'", agentName)).
        WithMetadata("missing_capabilities", missing).
        WithMetadata("excess_capabilities", excess)
    return s.LogEvent(ctx, actx, event)
}

// LogAgentCapabilityVerified logs when agent capabilities are verified successfully.
func (s *AuditService) LogAgentCapabilityVerified(
    ctx context.Context,
    actx AuditContext,
    agentID, agentName string,
    effectiveCapabilities, effectiveTools []string,
) error {
    event := NewSuccessEvent(audit.ActionAgentCapabilityVerified, audit.ResourceTypeAgent, agentID).
        WithResourceName(agentName).
        WithMessage(fmt.Sprintf("Agent '%s' capabilities verified", agentName)).
        WithMetadata("effective_capabilities", effectiveCapabilities).
        WithMetadata("effective_tools", effectiveTools)
    return s.LogEvent(ctx, actx, event)
}

// ============================================
// BOOTSTRAP TOKEN AUDIT EVENTS
// ============================================

// LogBootstrapTokenCreated logs when a bootstrap token is created.
func (s *AuditService) LogBootstrapTokenCreated(
    ctx context.Context,
    actx AuditContext,
    tokenID, tokenPrefix, description string,
    maxUses int,
    expiresAt time.Time,
) error {
    event := NewSuccessEvent(audit.ActionBootstrapTokenCreated, audit.ResourceTypeBootstrapToken, tokenID).
        WithResourceName(tokenPrefix).
        WithSeverity(audit.SeverityHigh).
        WithMessage(fmt.Sprintf("Bootstrap token %s created: %s", tokenPrefix, description)).
        WithMetadata("max_uses", maxUses).
        WithMetadata("expires_at", expiresAt)
    return s.LogEvent(ctx, actx, event)
}

// LogBootstrapTokenRevoked logs when a bootstrap token is revoked.
func (s *AuditService) LogBootstrapTokenRevoked(
    ctx context.Context,
    actx AuditContext,
    tokenID, tokenPrefix, reason string,
) error {
    event := NewSuccessEvent(audit.ActionBootstrapTokenRevoked, audit.ResourceTypeBootstrapToken, tokenID).
        WithResourceName(tokenPrefix).
        WithSeverity(audit.SeverityCritical).
        WithMessage(fmt.Sprintf("Bootstrap token %s revoked: %s", tokenPrefix, reason)).
        WithMetadata("reason", reason)
    return s.LogEvent(ctx, actx, event)
}

// LogBootstrapTokenUsed logs when a bootstrap token is used for registration.
func (s *AuditService) LogBootstrapTokenUsed(
    ctx context.Context,
    actx AuditContext,
    tokenID, tokenPrefix, agentID, agentName string,
    usesRemaining int,
) error {
    event := NewSuccessEvent(audit.ActionBootstrapTokenUsed, audit.ResourceTypeBootstrapToken, tokenID).
        WithResourceName(tokenPrefix).
        WithMessage(fmt.Sprintf("Bootstrap token %s used to register agent '%s'", tokenPrefix, agentName)).
        WithMetadata("agent_id", agentID).
        WithMetadata("agent_name", agentName).
        WithMetadata("uses_remaining", usesRemaining)
    return s.LogEvent(ctx, actx, event)
}
```

## Integration Points

### Platform Agent Service Integration

The following methods in `platform_agent_service.go` require audit logging:

| Method | Line | Required Audit Event | Priority |
|--------|------|---------------------|----------|
| `CreatePlatformAgent` | 550-591 | `agent.created` | Critical |
| `RegisterAgentWithToken` | 435-526 | `agent.registered`, `bootstrap_token.used` | Critical |
| `DisablePlatformAgent` | 594-607 | `agent.deactivated` | High |
| `EnablePlatformAgent` | 610-623 | `agent.activated` | High |
| `DeletePlatformAgent` | 626-639 | `agent.deleted` | Critical |
| `RecordHeartbeat` | 219-290 | `agent.heartbeat_started` (first time), `agent.connected` | Medium |
| `CreateBootstrapToken` | 330-366 | `bootstrap_token.created` | High |
| `RevokeBootstrapToken` | 392-408 | `bootstrap_token.revoked` | Critical |

### Updated Platform Agent Service

```go
// Updated PlatformAgentService with AuditService injection
type PlatformAgentService struct {
    agentRepo        agent.Repository
    commandRepo      command.Repository
    bootstrapRepo    agent.BootstrapTokenRepository
    registrationRepo agent.AgentRegistrationRepository
    agentState       *redis.AgentStateStore
    auditService     *AuditService  // Add audit service
    logger           *logger.Logger
}

// NewPlatformAgentService updated constructor
func NewPlatformAgentService(
    agentRepo agent.Repository,
    commandRepo command.Repository,
    bootstrapRepo agent.BootstrapTokenRepository,
    registrationRepo agent.AgentRegistrationRepository,
    agentState *redis.AgentStateStore,
    auditService *AuditService,  // Add parameter
    log *logger.Logger,
) *PlatformAgentService {
    return &PlatformAgentService{
        agentRepo:        agentRepo,
        commandRepo:      commandRepo,
        bootstrapRepo:    bootstrapRepo,
        registrationRepo: registrationRepo,
        agentState:       agentState,
        auditService:     auditService,
        logger:           log.With("service", "platform_agent"),
    }
}
```

### Example: Updated CreatePlatformAgent

```go
// CreatePlatformAgent creates a new platform agent (admin operation).
func (s *PlatformAgentService) CreatePlatformAgent(
    ctx context.Context,
    input CreatePlatformAgentInput,
    actorID, actorEmail string,  // Add actor info for audit
) (*CreatePlatformAgentOutput, error) {
    s.logger.Info("admin creating platform agent", "name", input.Name, "region", input.Region)

    // ... existing agent creation code ...

    if err := s.agentRepo.Create(ctx, a); err != nil {
        return nil, fmt.Errorf("failed to create agent: %w", err)
    }

    // Audit log: Agent created by admin
    auditCtx := AuditContext{
        TenantID:   SystemTenantID.String(),
        ActorID:    actorID,
        ActorEmail: actorEmail,
    }
    if err := s.auditService.LogAgentCreated(ctx, auditCtx, a.ID.String(), a.Name, string(a.Type)); err != nil {
        s.logger.Warn("failed to log agent creation audit", "error", err)
    }

    return &CreatePlatformAgentOutput{
        Agent:  a,
        APIKey: apiKey,
    }, nil
}
```

### Example: Updated RegisterAgentWithToken

```go
// RegisterAgentWithToken with comprehensive audit logging
func (s *PlatformAgentService) RegisterAgentWithToken(
    ctx context.Context,
    input RegisterAgentInput,
) (*RegisterAgentOutput, error) {
    // ... existing validation and agent creation code ...

    if err := s.agentRepo.Create(ctx, a); err != nil {
        return nil, fmt.Errorf("failed to create agent: %w", err)
    }

    // Increment token usage
    if err := s.bootstrapRepo.IncrementUsage(ctx, token.ID); err != nil {
        s.logger.Warn("failed to increment token usage", "error", err)
    }

    // Create audit context for agent self-registration
    auditCtx := AuditContext{
        TenantID:   SystemTenantID.String(),
        ActorID:    a.ID.String(),     // Agent is the actor
        ActorEmail: "agent:" + a.Name, // Use agent name as identifier
        ActorIP:    input.FromIP.String(),
    }

    // Audit log 1: Agent registered
    if err := s.auditService.LogAgentRegistered(
        ctx, auditCtx,
        a.ID.String(), a.Name, token.TokenPrefix, input.Region,
        input.Capabilities, input.Tools,
    ); err != nil {
        s.logger.Warn("failed to log agent registration audit", "error", err)
    }

    // Audit log 2: Bootstrap token used
    remainingUses := token.MaxUses - token.UsedCount - 1
    if err := s.auditService.LogBootstrapTokenUsed(
        ctx, auditCtx,
        token.ID.String(), token.TokenPrefix, a.ID.String(), a.Name, remainingUses,
    ); err != nil {
        s.logger.Warn("failed to log token usage audit", "error", err)
    }

    // Create registration audit record
    registration := agent.NewAgentRegistration(
        a.ID,
        &token.ID,
        input.FromIP,
        input.Hostname,
        a,
    )
    if err := s.registrationRepo.Create(ctx, registration); err != nil {
        s.logger.Warn("failed to create registration record", "error", err)
    }

    s.logger.Info("agent registered successfully", "agent_id", a.ID.String(), "name", a.Name)

    return &RegisterAgentOutput{
        Agent:  a,
        APIKey: apiKey,
    }, nil
}
```

### Heartbeat Audit Logging Policy

> ⚠️ **QUAN TRỌNG**: KHÔNG audit log mỗi heartbeat!
>
> **Lý do**: 1000 agents × 1 heartbeat/min × 60 min × 24 hours = **1,440,000 audit logs/day**
> → Database phình to, queries chậm, storage cost cao

**Chỉ audit log khi:**
1. Agent **comes online** (first heartbeat after being offline)
2. Agent **goes offline** (heartbeat timeout)
3. Agent **errors** (authentication failure, validation error)

```go
// RecordHeartbeat - CHỈ audit log khi state thay đổi
func (s *PlatformAgentService) RecordHeartbeat(ctx context.Context, input HeartbeatInput) error {
    agentID, err := shared.IDFromString(input.AgentID)
    if err != nil {
        return fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
    }

    // Check if this is the first heartbeat (agent coming online)
    wasOnline, _ := s.agentState.IsAgentOnline(ctx, agentID)

    // ... Redis operations (hot path, NO audit log) ...

    // ✅ CHỈ audit log khi agent CHUYỂN TRẠNG THÁI từ offline → online
    if !wasOnline {
        auditCtx := AuditContext{
            TenantID:   SystemTenantID.String(),
            ActorID:    agentID.String(),
            ActorEmail: "agent:" + agentName,
            ActorIP:    input.IPAddress,
        }

        // 1 audit log per SESSION, không phải per heartbeat
        if err := s.auditService.LogAgentConnected(
            ctx, auditCtx,
            agentID.String(), agentName, input.IPAddress,
        ); err != nil {
            s.logger.Warn("failed to log agent connection audit", "error", err)
        }
    }

    // ❌ KHÔNG có audit log cho regular heartbeats!
    // Thay vào đó, sử dụng structured logging cho debug:
    s.logger.Debug("heartbeat received",
        "agent_id", agentID,
        "ip", input.IPAddress,
        "current_jobs", input.CurrentJobs,
    )

    return nil
}
```

### Audit Log Frequency Summary

| Event | Audit Log | Frequency |
|-------|-----------|-----------|
| Regular heartbeat (every 60s) | ❌ KHÔNG | - |
| Agent comes online | ✅ `agent.connected` | 1 per session |
| Agent goes offline | ✅ `agent.disconnected` | 1 per session |
| Heartbeat auth error | ✅ `agent.auth_failed` | On error only |
| Capability drift | ✅ `agent.capability_drift` | On detection |

## Offline Detection Architecture

### Background Worker for Timeout Detection

```go
// AgentHealthMonitor monitors agent heartbeats and detects timeouts
type AgentHealthMonitor struct {
    agentRepo    agent.Repository
    agentState   *redis.AgentStateStore
    auditService *AuditService
    logger       *logger.Logger

    checkInterval time.Duration
    timeout       time.Duration
}

// NewAgentHealthMonitor creates a new health monitor
func NewAgentHealthMonitor(
    agentRepo agent.Repository,
    agentState *redis.AgentStateStore,
    auditService *AuditService,
    logger *logger.Logger,
) *AgentHealthMonitor {
    return &AgentHealthMonitor{
        agentRepo:     agentRepo,
        agentState:    agentState,
        auditService:  auditService,
        logger:        logger.With("worker", "agent_health_monitor"),
        checkInterval: 30 * time.Second,
        timeout:       90 * time.Second, // 1.5x heartbeat interval
    }
}

// Start begins the health monitoring loop
func (m *AgentHealthMonitor) Start(ctx context.Context) {
    ticker := time.NewTicker(m.checkInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            m.checkAgentHealth(ctx)
        }
    }
}

// checkAgentHealth checks all agents for heartbeat timeouts
func (m *AgentHealthMonitor) checkAgentHealth(ctx context.Context) {
    // Get all agents that were online but haven't sent heartbeat
    staleAgents, err := m.agentState.GetStaleAgents(ctx, m.timeout)
    if err != nil {
        m.logger.Error("failed to get stale agents", "error", err)
        return
    }

    for _, agentID := range staleAgents {
        // Get agent details for logging
        a, err := m.agentRepo.GetPlatformAgentByID(ctx, agentID)
        if err != nil {
            m.logger.Warn("failed to get agent for disconnect log", "agent_id", agentID, "error", err)
            continue
        }

        // Mark as offline in Redis
        if err := m.agentState.MarkAgentOffline(ctx, agentID); err != nil {
            m.logger.Warn("failed to mark agent offline", "agent_id", agentID, "error", err)
        }

        // Update database
        a.UpdateHealth("offline")
        if err := m.agentRepo.Update(ctx, a); err != nil {
            m.logger.Warn("failed to update agent health", "agent_id", agentID, "error", err)
        }

        // Audit log: Agent disconnected
        auditCtx := AuditContext{
            TenantID:   SystemTenantID.String(),
            ActorEmail: "system:health_monitor",
        }

        if err := m.auditService.LogAgentDisconnected(
            ctx, auditCtx,
            a.ID.String(), a.Name,
        ); err != nil {
            m.logger.Warn("failed to log agent disconnect audit", "error", err)
        }

        m.logger.Info("agent went offline",
            "agent_id", a.ID.String(),
            "agent_name", a.Name,
            "last_seen", a.LastSeenAt,
        )
    }
}
```

## Audit Event Schema

### Standard Audit Event Fields

```json
{
    "id": "uuid",
    "tenant_id": "uuid",
    "action": "agent.connected",
    "resource_type": "agent",
    "resource_id": "uuid",
    "resource_name": "prod-scanner-01",
    "actor_id": "uuid",
    "actor_email": "agent:prod-scanner-01",
    "actor_ip": "10.0.1.50",
    "result": "success",
    "severity": "low",
    "message": "Agent 'prod-scanner-01' connected from 10.0.1.50",
    "metadata": {
        "ip_address": "10.0.1.50",
        "version": "1.2.3"
    },
    "logged_at": "2024-01-15T10:30:00Z"
}
```

### Event Severity Levels

| Action | Severity | Rationale |
|--------|----------|-----------|
| `agent.created` | Medium | New resource created |
| `agent.registered` | Medium | Self-registration |
| `agent.activated` | Medium | Status change |
| `agent.deactivated` | High | Security-relevant |
| `agent.deleted` | Critical | Permanent action |
| `agent.revoked` | Critical | Security emergency |
| `agent.connected` | Low | Normal operation |
| `agent.disconnected` | Low | Normal operation |
| `agent.capability_drift` | High | Security concern |
| `bootstrap_token.created` | High | Security credential |
| `bootstrap_token.revoked` | Critical | Security action |
| `bootstrap_token.used` | Low | Normal operation |

## Querying Audit Logs

### Common Query Patterns

```sql
-- Find all agent lifecycle events
SELECT * FROM audit_logs
WHERE resource_type = 'agent'
  AND action IN ('agent.created', 'agent.deleted', 'agent.activated', 'agent.deactivated')
ORDER BY logged_at DESC;

-- Find connection history for an agent
SELECT * FROM audit_logs
WHERE resource_type = 'agent'
  AND resource_id = :agent_id
  AND action IN ('agent.connected', 'agent.disconnected')
ORDER BY logged_at DESC;

-- Find all agents registered via a specific bootstrap token
SELECT * FROM audit_logs
WHERE action = 'agent.registered'
  AND metadata->>'bootstrap_token_prefix' = :token_prefix
ORDER BY logged_at DESC;

-- Find all capability drift events (security monitoring)
SELECT * FROM audit_logs
WHERE action = 'agent.capability_drift'
  AND severity = 'high'
ORDER BY logged_at DESC;

-- Security audit: all critical agent actions in last 24h
SELECT * FROM audit_logs
WHERE resource_type IN ('agent', 'bootstrap_token')
  AND severity = 'critical'
  AND logged_at > NOW() - INTERVAL '24 hours'
ORDER BY logged_at DESC;
```

### API Endpoints for Audit Queries

```go
// GET /api/v1/platform/agents/:id/audit-history
// Returns audit logs for a specific agent

// GET /api/v1/platform/agents/audit-logs
// Query parameters:
//   - action: Filter by action type
//   - severity: Filter by severity level
//   - since: Start timestamp
//   - until: End timestamp
//   - actor_id: Filter by actor
```

## Implementation Plan

### Phase 1: Domain Model Updates (Day 1)

| Task | File | Status |
|------|------|--------|
| Add new audit actions | `domain/audit/value_objects.go` | Pending |
| Add new resource types | `domain/audit/value_objects.go` | Pending |
| Update IsValid() switch | `domain/audit/value_objects.go` | Pending |
| Update Category() switch | `domain/audit/value_objects.go` | Pending |
| Update SeverityForAction() | `domain/audit/value_objects.go` | Pending |

### Phase 2: Service Layer Extensions (Day 2)

| Task | File | Status |
|------|------|--------|
| Add LogAgentRegistered() | `app/audit_service.go` | Pending |
| Add LogAgentHeartbeatStarted() | `app/audit_service.go` | Pending |
| Add LogAgentHeartbeatTimeout() | `app/audit_service.go` | Pending |
| Add LogAgentCapabilityDrift() | `app/audit_service.go` | Pending |
| Add LogAgentCapabilityVerified() | `app/audit_service.go` | Pending |
| Add LogBootstrapTokenCreated() | `app/audit_service.go` | Pending |
| Add LogBootstrapTokenRevoked() | `app/audit_service.go` | Pending |
| Add LogBootstrapTokenUsed() | `app/audit_service.go` | Pending |

### Phase 3: Platform Agent Service Integration (Day 3-4)

| Task | File | Status |
|------|------|--------|
| Inject AuditService dependency | `app/platform_agent_service.go` | Pending |
| Update CreatePlatformAgent() | `app/platform_agent_service.go` | Pending |
| Update RegisterAgentWithToken() | `app/platform_agent_service.go` | Pending |
| Update DisablePlatformAgent() | `app/platform_agent_service.go` | Pending |
| Update EnablePlatformAgent() | `app/platform_agent_service.go` | Pending |
| Update DeletePlatformAgent() | `app/platform_agent_service.go` | Pending |
| Update RecordHeartbeat() | `app/platform_agent_service.go` | Pending |
| Update CreateBootstrapToken() | `app/platform_agent_service.go` | Pending |
| Update RevokeBootstrapToken() | `app/platform_agent_service.go` | Pending |

### Phase 4: Health Monitor Worker (Day 5)

| Task | File | Status |
|------|------|--------|
| Create AgentHealthMonitor | `app/agent_health_monitor.go` | Pending |
| Add GetStaleAgents() to AgentStateStore | `infra/redis/agent_state.go` | Pending |
| Add MarkAgentOffline() to AgentStateStore | `infra/redis/agent_state.go` | Pending |
| Register worker in main.go | `cmd/api/main.go` | Pending |
| Add unit tests | `app/agent_health_monitor_test.go` | Pending |

### Phase 5: Testing & Documentation (Day 5)

| Task | File | Status |
|------|------|--------|
| Integration tests for audit logging | `tests/integration/agent_audit_test.go` | Pending |
| Update API documentation | `docs/api/` | Pending |
| Add audit log queries to admin dashboard | UI component | Pending |

## Success Metrics

### Audit Coverage Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Agent Lifecycle Coverage | 100% | All create/update/delete logged |
| Connection Events Coverage | 100% | All connect/disconnect logged |
| Bootstrap Token Coverage | 100% | All token operations logged |
| No Missing Audit Entries | < 0.1% | Compare operations vs audit logs |

### Query Performance

| Query Type | Target Latency | Index Support |
|------------|----------------|---------------|
| Single agent history | < 50ms | `idx_audit_resource_id` |
| Time range queries | < 200ms | `idx_audit_logged_at` |
| Action type queries | < 100ms | `idx_audit_action` |
| Full-text search | < 500ms | `idx_audit_message_gin` |

## Security Considerations

### Audit Log Protection

1. **Immutability**: Audit logs are append-only, no updates or deletes
2. **Retention**: Minimum 90 days for compliance, configurable up to 2 years
3. **Access Control**: Only admin users can query audit logs
4. **Encryption**: Audit logs encrypted at rest in database

### Sensitive Data Handling

1. **No Secrets**: Never log API keys, tokens, or passwords
2. **IP Addresses**: Logged for security but can be anonymized for GDPR
3. **Metadata Filtering**: Review metadata for PII before logging
4. **Token Prefixes Only**: Log only first 6 chars of bootstrap tokens

## Related Documents

- [Agent Capability Verification Architecture](./agent-capability-verification.md)
- [Heartbeat Performance Optimization](./heartbeat-optimization.md)
- [Platform Security Model](./platform-security.md)

## Appendix: Complete Action Reference

### All Agent-Related Audit Actions

| Action | Description | When Logged |
|--------|-------------|-------------|
| `agent.created` | Agent created by admin | Admin creates platform agent |
| `agent.registered` | Agent self-registered | Agent uses bootstrap token |
| `agent.updated` | Agent configuration changed | Any agent field updated |
| `agent.activated` | Agent enabled | Admin enables agent |
| `agent.deactivated` | Agent disabled | Admin disables agent |
| `agent.deleted` | Agent deleted | Admin deletes agent |
| `agent.revoked` | Agent access revoked | Emergency security action |
| `agent.key_regenerated` | API key regenerated | Admin regenerates key |
| `agent.connected` | Agent came online | First heartbeat after offline |
| `agent.disconnected` | Agent went offline | Heartbeat timeout |
| `agent.capability_drift` | Capability mismatch | Reported != Declared |
| `agent.capability_verified` | Capabilities verified | Effective capabilities computed |

### All Bootstrap Token Actions

| Action | Description | When Logged |
|--------|-------------|-------------|
| `bootstrap_token.created` | Token created | Admin creates token |
| `bootstrap_token.revoked` | Token revoked | Admin revokes token |
| `bootstrap_token.used` | Token used for registration | Agent registers with token |
| `bootstrap_token.expired` | Token expired | Background job detects expiry |
| `bootstrap_token.exhausted` | Token max uses reached | Last use consumed |
