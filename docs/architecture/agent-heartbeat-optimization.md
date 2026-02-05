# Agent Heartbeat Performance Optimization

## Overview

This document describes the optimized heartbeat architecture for Platform Agents. The goal is to achieve real-time agent monitoring with minimal database load while maintaining data integrity for operational decisions.

**Core Principle**: "Redis for real-time, Database for persistence - sync only when necessary"

## Problem Statement

### Current Architecture Analysis

**Current Flow (platform_agent_service.go:219-290):**
```
Agent sends heartbeat every 60s
         │
         ▼
┌─────────────────────────────────────┐
│ RecordHeartbeat()                   │
│ 1. DB READ: GetPlatformAgentByID()  │  ← Unnecessary for every heartbeat
│ 2. Update agent metrics in memory   │
│ 3. DB WRITE: agentRepo.Update()     │  ← High frequency writes
│ 4. Redis: RecordHeartbeat()         │  ← Correct, already implemented
│ 5. Redis: SetPlatformAgentState()   │  ← Correct, already implemented
└─────────────────────────────────────┘
```

### Performance Impact

| Metric | Current | With 100 Agents | With 1000 Agents |
|--------|---------|-----------------|------------------|
| DB Reads/min | 1 per heartbeat | 100/min | 1000/min |
| DB Writes/min | 1 per heartbeat | 100/min | 1000/min |
| Total DB ops/hour | 2 per heartbeat | 12,000/hour | 120,000/hour |
| Redis ops/min | 2 per heartbeat | 200/min | 2000/min |

### Key Insights

1. **Heartbeat data is ephemeral**: TTL 2 minutes in Redis, no long-term storage needed
2. **Database writes are unnecessary**: Heartbeat status doesn't need persistence
3. **Redis is already used correctly**: `agent_state.go` already implements Redis-first storage
4. **The problem is in the service layer**: `platform_agent_service.go` adds unnecessary DB operations

## Recommended Architecture

### Decision: Hybrid Approach (Redis + Database for State Changes)

Sau khi phân tích, chúng ta cần **Hybrid approach** để vừa tối ưu performance vừa đảm bảo có thể query lịch sử online/offline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HYBRID STORAGE STRATEGY                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   REDIS (Real-time - Every Heartbeat)     DATABASE (Persistence - On Change)│
│   ──────────────────────────────────      ──────────────────────────────────│
│   • Current heartbeat (TTL 2min)          • last_seen_at                    │
│   • Online status                         • last_online_at                  │
│   • Load metrics (CPU, Memory)            • last_offline_at                 │
│   • Current job count                     • Agent config (static)           │
│   • Load score                            • Audit logs                      │
│                                                                              │
│   Updated: Every 60 seconds               Updated: Only on state transition │
│   Purpose: Real-time monitoring           Purpose: Historical queries       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Storage Decision Matrix

| Data Type | Storage | Update Frequency | Rationale |
|-----------|---------|------------------|-----------|
| Current heartbeat | Redis | Every 60s | Real-time, TTL-based |
| Current jobs count | Redis | Every 60s | Changes frequently |
| CPU/Memory metrics | Redis | Every 60s | Point-in-time, no history |
| Load score | Redis | Every 60s | Computed, changes frequently |
| **last_seen_at** | **Database** | **On heartbeat (state transition only)** | **Serves as "last online time"** |
| **last_offline_at** | **Database** | **On disconnect** | **Track when agent went offline** |
| Session stats | Database | On session end | Per-session findings/scans/errors |
| Daily aggregates | Database | Daily | Time-series analytics |
| Agent config | Database | Rarely | Static, admin-controlled |
| Agent status | Database | Rarely | Administrative action |

> **Note**: Schema đã được đơn giản hóa từ 3 timestamps (last_seen_at, last_online_at, last_offline_at) xuống còn 2. `last_seen_at` đóng vai trò "last online time" vì nó được cập nhật với mỗi heartbeat thành công.

### Why Hybrid? The Admin Query Problem

**Với Redis-only, admin KHÔNG THỂ trả lời:**
- "Agent X offline lúc nào?" → ❌ Dữ liệu mất sau 2 phút
- "Agent X online lần cuối khi nào?" → ❌ Chỉ biết nếu đang online
- "Thời gian uptime của agent?" → ❌ Không có lịch sử

**Với Hybrid approach:**
- "Agent X offline lúc nào?" → ✅ `SELECT last_offline_at FROM agents WHERE id = X`
- "Agent X online lần cuối khi nào?" → ✅ `SELECT last_online_at FROM agents WHERE id = X`
- "Thời gian uptime?" → ✅ `last_offline_at - last_online_at`

### Database Schema for Online Tracking

```sql
-- Simplified schema: only add last_offline_at
-- last_seen_at already exists and serves as "last online time"
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS last_offline_at TIMESTAMP WITH TIME ZONE;

-- Index for querying offline agents
CREATE INDEX IF NOT EXISTS idx_agents_last_offline_at
ON agents (last_offline_at DESC)
WHERE last_offline_at IS NOT NULL;

-- Partial index for finding stale offline agents
CREATE INDEX IF NOT EXISTS idx_agents_stale_offline
ON agents (last_offline_at)
WHERE status = 'active' AND last_offline_at IS NOT NULL;
```

### Session Tracking Tables

```sql
-- Agent sessions: track per-session statistics
CREATE TABLE IF NOT EXISTS agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Session timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER GENERATED ALWAYS AS (
        CASE WHEN ended_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (ended_at - started_at))::INTEGER
             ELSE NULL
        END
    ) STORED,

    -- Session stats
    findings_count INTEGER NOT NULL DEFAULT 0,
    scans_count INTEGER NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    jobs_completed INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    version TEXT,
    hostname TEXT,
    ip_address INET,
    region TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Daily aggregated stats for time-series analytics
CREATE TABLE IF NOT EXISTS agent_daily_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    date DATE NOT NULL,

    -- Daily aggregates
    total_findings INTEGER NOT NULL DEFAULT 0,
    total_scans INTEGER NOT NULL DEFAULT 0,
    total_errors INTEGER NOT NULL DEFAULT 0,
    total_jobs INTEGER NOT NULL DEFAULT 0,

    -- Uptime stats
    online_seconds INTEGER NOT NULL DEFAULT 0,
    offline_seconds INTEGER NOT NULL DEFAULT 0,
    session_count INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    UNIQUE(agent_id, date)
);
```

### What Gets Updated When

```
┌────────────────────────────────────────────────────────────────────────────┐
│                    DATABASE UPDATE TRIGGERS                                 │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   EVENT                           DATABASE UPDATE                           │
│   ─────                           ───────────────                           │
│                                                                             │
│   Agent sends heartbeat           ❌ NO DB UPDATE (Redis only)              │
│   (every 60s)                                                               │
│                                                                             │
│   Agent comes online              ✅ UPDATE agents SET                      │
│   (first heartbeat after          │     last_seen_at = NOW(),               │
│    being offline)                 │     health = 'online'                   │
│                                   │  WHERE id = :agent_id                   │
│                                   ✅ INSERT INTO agent_sessions (start)     │
│                                                                             │
│   Agent goes offline              ✅ UPDATE agents SET                      │
│   (heartbeat timeout              │     last_offline_at = NOW(),            │
│    detected by monitor)           │     health = 'offline'                  │
│                                   │  WHERE id = :agent_id                   │
│                                   ✅ UPDATE agent_sessions SET ended_at     │
│                                   ✅ UPDATE agent_daily_stats (upsert)      │
│                                                                             │
│   Version changes                 ✅ UPDATE agents SET version = :v         │
│   (rare, agent restart)                                                     │
│                                                                             │
│   Admin updates config            ✅ UPDATE agents SET ... (normal CRUD)    │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### Performance: Hybrid vs Full DB

| Scenario | Full DB (Current) | Hybrid (Proposed) | Improvement |
|----------|-------------------|-------------------|-------------|
| 1000 agents, 1 hour | 120,000 DB writes | ~200 DB writes | **99.8% reduction** |
| Agent uptime 24 hours | 1,440 DB writes | 2 DB writes | **99.9% reduction** |
| Can query last online? | ✅ Yes | ✅ Yes | Same |
| Can query last offline? | ❌ No | ✅ Yes | Better |

### What Should NOT Be in Database (Real-time Only)

```go
// These fields are Redis-only, NOT written to DB during heartbeat:
- CurrentJobs     // Real-time metric
- LoadScore       // Computed every heartbeat
- CPUPercent      // Point-in-time metric
- MemoryPercent   // Point-in-time metric
- Health          // Derived from heartbeat presence in Redis
```

### What Should Be in Database (State Tracking)

```go
// Agent model with simplified online tracking (2 timestamps instead of 3)
type Agent struct {
    // Identity & Configuration (updated rarely by admin)
    ID, Name, Description
    Type, ExecutionMode
    DeclaredCapabilities/Tools
    EffectiveCapabilities/Tools
    Status (active/disabled)
    Version
    Region
    CreatedAt, UpdatedAt

    // Online Tracking (simplified - 2 fields instead of 3)
    LastSeenAt    *time.Time  // Last heartbeat = effectively "last online time"
    LastOfflineAt *time.Time  // When agent went offline (heartbeat timeout)
}

// AgentSession for per-session tracking
type AgentSession struct {
    ID            shared.ID
    AgentID       shared.ID
    StartedAt     time.Time
    EndedAt       *time.Time
    FindingsCount int
    ScansCount    int
    ErrorsCount   int
    JobsCompleted int
}

// AgentDailyStats for time-series analytics
type AgentDailyStats struct {
    ID            shared.ID
    AgentID       shared.ID
    Date          time.Time
    TotalFindings int
    TotalScans    int
    OnlineSeconds int
    SessionCount  int
}
```

## Optimized Architecture

### New Heartbeat Flow (Hybrid)

```
Agent sends heartbeat every 60s
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│ RecordHeartbeat() - HYBRID OPTIMIZED                            │
│                                                                  │
│ 1. Validate agent ID format                    ← No DB call     │
│ 2. Redis: Check if agent was online before     ← Fast lookup    │
│ 3. Redis: Get cached agent config              ← Fast lookup    │
│ 4. Redis: RecordHeartbeat()                    ← Always         │
│ 5. Redis: SetPlatformAgentState()              ← Always         │
│                                                                  │
│ 6. IF agent was OFFLINE before (first heartbeat):               │
│    └── DB: UPDATE last_seen_at = NOW()         ← 1 write/session│
│    └── DB: INSERT INTO agent_sessions          ← Start session  │
│    └── Audit: LogAgentConnected()              ← 1 log/session  │
│                                                                  │
│ 7. IF version changed:                                          │
│    └── DB: UPDATE version                      ← Rare           │
│                                                                  │
│ HOT PATH: Redis only (99.9% of heartbeats)                      │
│ COLD PATH: DB write only on state change (0.1%)                 │
│                                                                  │
│ ⚠️  KHÔNG audit log mỗi heartbeat - chỉ log state changes!      │
└─────────────────────────────────────────────────────────────────┘
```

### Offline Detection Flow

```
Background HealthMonitor runs every 30 seconds
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│ checkAndMarkOfflineAgents()                                      │
│                                                                  │
│ 1. Redis: Get agents with stale heartbeat (> 90s)               │
│                                                                  │
│ FOR EACH stale agent:                                            │
│ 2. Redis: Get last heartbeat timestamp                          │
│ 3. Redis: Remove from online set                                │
│ 4. DB: UPDATE last_seen_at = :last_heartbeat,                   │
│         last_offline_at = NOW()                    ← 1 write    │
│ 5. Audit: LogAgentDisconnected()                                │
│                                                                  │
│ DB writes: Only when agents go offline (rare event)             │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HEARTBEAT ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐         ┌──────────────┐         ┌──────────────────────┐ │
│  │   Agent 1    │         │   Agent 2    │         │    Agent N           │ │
│  │  Heartbeat   │         │  Heartbeat   │         │   Heartbeat          │ │
│  └──────┬───────┘         └──────┬───────┘         └──────────┬───────────┘ │
│         │                        │                            │              │
│         └────────────────────────┼────────────────────────────┘              │
│                                  │                                           │
│                                  ▼                                           │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         API Gateway                                    │  │
│  │                    PUT /platform/heartbeat                             │  │
│  └───────────────────────────────┬───────────────────────────────────────┘  │
│                                  │                                           │
│                                  ▼                                           │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    PlatformAgentService                                │  │
│  │                    RecordHeartbeat()                                   │  │
│  │                                                                        │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  HOT PATH (Every Heartbeat - Redis Only)                        │ │  │
│  │   │  • Validate agent ID                                            │ │  │
│  │   │  • Store heartbeat in Redis (TTL 2min)                          │ │  │
│  │   │  • Update platform agent state in Redis (TTL 10min)             │ │  │
│  │   │  • Update online agents sorted set                              │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                                                        │  │
│  │   ┌─────────────────────────────────────────────────────────────────┐ │  │
│  │   │  COLD PATH (On State Change Only - Database)                    │ │  │
│  │   │  • First connection: Update status to "active"                  │ │  │
│  │   │  • Version change: Update version field                         │ │  │
│  │   │  • Capability change: Trigger verification flow                 │ │  │
│  │   └─────────────────────────────────────────────────────────────────┘ │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                  │                                           │
│         ┌────────────────────────┴─────────────────────────┐                │
│         │                                                   │                │
│         ▼                                                   ▼                │
│  ┌──────────────────┐                              ┌──────────────────┐     │
│  │      REDIS       │                              │    PostgreSQL    │     │
│  │   (Primary)      │                              │   (Secondary)    │     │
│  │                  │                              │                  │     │
│  │ • Heartbeat TTL  │      Background Sync         │ • Agent config   │     │
│  │ • Agent state    │ ─────────────────────────►   │ • Audit logs     │     │
│  │ • Online set     │      (Every 5 minutes)       │ • Historical     │     │
│  │ • Load scores    │                              │                  │     │
│  └──────────────────┘                              └──────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Implementation

### Optimized RecordHeartbeat

```go
// RecordHeartbeat - Optimized version with Redis-only hot path
func (s *PlatformAgentService) RecordHeartbeat(ctx context.Context, input HeartbeatInput) error {
    // 1. Validate agent ID format only (no DB lookup)
    agentID, err := shared.IDFromString(input.AgentID)
    if err != nil {
        return fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
    }

    // 2. Check if agent was previously online (for first-connection detection)
    wasOnline, _ := s.agentState.IsAgentOnline(ctx, agentID)

    // 3. Get cached agent config from Redis (or load from DB if cache miss)
    agentConfig, err := s.getAgentConfigCached(ctx, agentID)
    if err != nil {
        return fmt.Errorf("agent not found or not authorized: %w", err)
    }

    // 4. Calculate load score
    loadScore := calculateLoadScore(input.CurrentJobs, input.MaxConcurrent, input.CPUPercent, input.MemoryPercent)

    // 5. Store heartbeat in Redis (HOT PATH - always executed)
    hb := &redis.AgentHeartbeat{
        AgentID:       input.AgentID,
        IsPlatform:    true,
        Status:        "active",
        Health:        "online",
        CurrentJobs:   input.CurrentJobs,
        MaxConcurrent: input.MaxConcurrent,
        IPAddress:     input.IPAddress,
        Version:       input.Version,
        CPUPercent:    input.CPUPercent,
        MemoryPercent: input.MemoryPercent,
        LoadScore:     loadScore,
    }

    if err := s.agentState.RecordHeartbeat(ctx, hb); err != nil {
        return fmt.Errorf("failed to record heartbeat: %w", err)
    }

    // 6. Update platform agent state in Redis
    state := &redis.PlatformAgentState{
        AgentID:       input.AgentID,
        Health:        "online",
        CurrentJobs:   input.CurrentJobs,
        MaxConcurrent: input.MaxConcurrent,
        Region:        agentConfig.Region,
        Capabilities:  agentConfig.EffectiveCapabilities,
        Tools:         agentConfig.EffectiveTools,
        CPUPercent:    input.CPUPercent,
        MemoryPercent: input.MemoryPercent,
        LoadScore:     loadScore,
        LastHeartbeat: time.Now(),
    }

    if err := s.agentState.SetPlatformAgentState(ctx, state); err != nil {
        s.logger.Warn("failed to update agent state", "error", err)
    }

    // 7. COLD PATH: Handle state changes (first connection, version change)
    if !wasOnline {
        s.handleAgentCameOnline(ctx, agentID, agentConfig.Name, input.IPAddress, input.Version)
    } else if agentConfig.Version != input.Version && input.Version != "" {
        s.handleVersionChange(ctx, agentID, agentConfig.Version, input.Version)
    }

    return nil
}

// getAgentConfigCached retrieves agent config from Redis cache, falling back to DB
func (s *PlatformAgentService) getAgentConfigCached(ctx context.Context, agentID shared.ID) (*AgentConfig, error) {
    // Try Redis cache first
    config, err := s.agentState.GetAgentConfig(ctx, agentID)
    if err == nil && config != nil {
        return config, nil
    }

    // Cache miss - load from database
    agent, err := s.agentRepo.GetPlatformAgentByID(ctx, agentID)
    if err != nil {
        return nil, err
    }

    // Cache for future use
    config = &AgentConfig{
        ID:                    agent.ID.String(),
        Name:                  agent.Name,
        Region:                agent.Region,
        EffectiveCapabilities: agent.EffectiveCapabilities,
        EffectiveTools:        agent.EffectiveTools,
        Version:               agent.Version,
    }

    if err := s.agentState.SetAgentConfig(ctx, config); err != nil {
        s.logger.Warn("failed to cache agent config", "error", err)
    }

    return config, nil
}

// handleAgentCameOnline handles first connection (COLD PATH)
// This is the ONLY place where we write to DB during heartbeat flow
func (s *PlatformAgentService) handleAgentCameOnline(ctx context.Context, agentID shared.ID, name, ip, version string) {
    // 1. Update last_online_at in database (HYBRID: persist for query)
    if err := s.agentRepo.UpdateOnlineTimestamp(ctx, agentID); err != nil {
        s.logger.Warn("failed to update online timestamp", "error", err)
    }

    // 2. Audit log: Agent connected (async to not block heartbeat)
    go func() {
        auditCtx := AuditContext{
            TenantID:   SystemTenantID.String(),
            ActorID:    agentID.String(),
            ActorEmail: "agent:" + name,
            ActorIP:    ip,
        }
        if err := s.auditService.LogAgentConnected(context.Background(), auditCtx, agentID.String(), name, ip); err != nil {
            s.logger.Warn("failed to log agent connection", "error", err)
        }
    }()

    s.logger.Info("agent came online", "agent_id", agentID.String(), "name", name, "ip", ip, "version", version)
}

// Repository method for updating online timestamp
// UpdateOnlineTimestamp updates only the last_online_at field
func (r *AgentRepository) UpdateOnlineTimestamp(ctx context.Context, agentID shared.ID) error {
    query := `UPDATE agents SET last_online_at = NOW(), updated_at = NOW() WHERE id = $1`
    _, err := r.db.ExecContext(ctx, query, agentID)
    return err
}

// handleVersionChange handles agent version update (COLD PATH)
func (s *PlatformAgentService) handleVersionChange(ctx context.Context, agentID shared.ID, oldVersion, newVersion string) {
    // Update version in database (rare operation)
    if err := s.agentRepo.UpdateVersion(ctx, agentID, newVersion); err != nil {
        s.logger.Warn("failed to update agent version", "error", err)
    }

    // Invalidate config cache
    s.agentState.InvalidateAgentConfig(ctx, agentID)

    s.logger.Info("agent version changed", "agent_id", agentID.String(), "old", oldVersion, "new", newVersion)
}

// calculateLoadScore computes weighted load score (lower is better)
func calculateLoadScore(currentJobs, maxConcurrent int, cpu, memory float64) float64 {
    if maxConcurrent == 0 {
        return 100.0 // Fully loaded
    }

    jobRatio := float64(currentJobs) / float64(maxConcurrent)
    resourceScore := (cpu + memory) / 200.0 // Normalized 0-1

    // Weighted: 70% job capacity, 30% resource utilization
    return jobRatio*0.7 + resourceScore*0.3
}
```

### Agent Config Cache in Redis

```go
// AgentConfig represents cached agent configuration
type AgentConfig struct {
    ID                    string   `json:"id"`
    Name                  string   `json:"name"`
    Region                string   `json:"region"`
    EffectiveCapabilities []string `json:"effective_capabilities"`
    EffectiveTools        []string `json:"effective_tools"`
    Version               string   `json:"version"`
    CachedAt              time.Time `json:"cached_at"`
}

const (
    agentConfigKey    = "agent:config:%s"  // agent:config:{agent_id}
    agentConfigTTL    = 30 * time.Minute   // Cache for 30 minutes
)

// SetAgentConfig caches agent configuration
func (s *AgentStateStore) SetAgentConfig(ctx context.Context, config *AgentConfig) error {
    key := fmt.Sprintf(agentConfigKey, config.ID)
    config.CachedAt = time.Now()

    data, err := json.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }

    return s.client.Set(ctx, key, string(data), agentConfigTTL)
}

// GetAgentConfig retrieves cached agent configuration
func (s *AgentStateStore) GetAgentConfig(ctx context.Context, agentID shared.ID) (*AgentConfig, error) {
    key := fmt.Sprintf(agentConfigKey, agentID.String())

    data, err := s.client.Get(ctx, key)
    if err != nil {
        if errors.Is(err, ErrKeyNotFound) {
            return nil, nil
        }
        return nil, err
    }

    var config AgentConfig
    if err := json.Unmarshal([]byte(data), &config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }

    return &config, nil
}

// InvalidateAgentConfig removes agent config from cache
func (s *AgentStateStore) InvalidateAgentConfig(ctx context.Context, agentID shared.ID) error {
    key := fmt.Sprintf(agentConfigKey, agentID.String())
    return s.client.Del(ctx, key)
}
```

## Redis Data Structure Design

### Key Patterns

| Key Pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `agent:heartbeat:{id}` | String (JSON) | 2 min | Latest heartbeat data |
| `agent:config:{id}` | String (JSON) | 30 min | Cached agent config |
| `platform:agent:status:{id}` | String (JSON) | 10 min | Platform agent state |
| `platform:agents:online` | Sorted Set | N/A | Online agents by last seen |

### Memory Estimation

```
Per Agent:
- Heartbeat: ~500 bytes
- Config cache: ~300 bytes
- State: ~400 bytes
- Sorted set member: ~40 bytes
Total: ~1.2 KB per agent

With 1000 agents: ~1.2 MB
With 10000 agents: ~12 MB
```

### TTL Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TTL STRATEGY                                     │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Heartbeat Interval: 60 seconds                                        │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ agent:heartbeat:{id}  TTL = 2 minutes                           │  │
│   │                                                                  │  │
│   │ Timeline:                                                        │  │
│   │ t=0      t=60s     t=120s    t=180s                             │  │
│   │ [HB]     [HB]      [HB]      [HB]                                │  │
│   │ │        │         │         │                                   │  │
│   │ └──2min──┘         │         │                                   │  │
│   │          └──2min───┘         │                                   │  │
│   │                    └──2min───┘                                   │  │
│   │                                                                  │  │
│   │ If heartbeat missed at t=60s:                                    │  │
│   │ t=0      t=60s     t=120s                                        │  │
│   │ [HB]     [MISS]    [EXPIRED] → Agent considered offline          │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ agent:config:{id}  TTL = 30 minutes                             │  │
│   │                                                                  │  │
│   │ Purpose: Avoid DB read on every heartbeat                        │  │
│   │ Invalidation: On admin config change or version change          │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │ platform:agents:online  No TTL (sorted set)                      │  │
│   │                                                                  │  │
│   │ Cleanup: Members removed when score < (now - 10 minutes)         │  │
│   │ Score: Unix timestamp of last heartbeat                          │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

## Offline Detection

### Background Health Monitor

```go
// AgentHealthMonitor monitors agent heartbeats and detects timeouts
type AgentHealthMonitor struct {
    agentState   *redis.AgentStateStore
    agentRepo    agent.Repository
    auditService *AuditService
    logger       *logger.Logger

    checkInterval time.Duration
    offlineThreshold time.Duration
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
            m.checkAndMarkOfflineAgents(ctx)
        }
    }
}

// checkAndMarkOfflineAgents finds agents that haven't sent heartbeat
// HYBRID: Updates database with offline timestamp for historical queries
func (m *AgentHealthMonitor) checkAndMarkOfflineAgents(ctx context.Context) {
    // Get all agents from online set with stale timestamps
    cutoff := time.Now().Add(-m.offlineThreshold)
    staleAgents, err := m.agentState.GetAgentsOlderThan(ctx, cutoff)
    if err != nil {
        m.logger.Error("failed to get stale agents", "error", err)
        return
    }

    for _, agentID := range staleAgents {
        // Get last heartbeat time from Redis before removing
        lastHeartbeat, _ := m.agentState.GetLastHeartbeatTime(ctx, agentID)

        // Get agent name for logging
        config, _ := m.agentState.GetAgentConfig(ctx, agentID)
        agentName := "unknown"
        if config != nil {
            agentName = config.Name
        }

        // 1. Remove from Redis online set
        if err := m.agentState.MarkAgentOffline(ctx, agentID); err != nil {
            m.logger.Warn("failed to mark agent offline in redis", "agent_id", agentID, "error", err)
        }

        // 2. HYBRID: Update database with offline timestamps
        if err := m.agentRepo.UpdateOfflineTimestamp(ctx, agentID, lastHeartbeat); err != nil {
            m.logger.Warn("failed to update offline timestamp in db", "agent_id", agentID, "error", err)
        }

        // 3. Audit log: Agent disconnected
        auditCtx := AuditContext{
            TenantID:   SystemTenantID.String(),
            ActorEmail: "system:health_monitor",
        }
        if err := m.auditService.LogAgentDisconnected(ctx, auditCtx, agentID.String(), agentName); err != nil {
            m.logger.Warn("failed to log agent disconnect", "error", err)
        }

        m.logger.Info("agent went offline",
            "agent_id", agentID,
            "name", agentName,
            "last_seen", lastHeartbeat,
        )
    }
}

// Repository method for updating offline timestamp
// UpdateOfflineTimestamp updates last_seen_at and last_offline_at when agent goes offline
func (r *AgentRepository) UpdateOfflineTimestamp(ctx context.Context, agentID shared.ID, lastSeen time.Time) error {
    query := `
        UPDATE agents
        SET last_seen_at = $2,
            last_offline_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
    `
    _, err := r.db.ExecContext(ctx, query, agentID, lastSeen)
    return err
}

// Redis method to get last heartbeat time
func (s *AgentStateStore) GetLastHeartbeatTime(ctx context.Context, agentID shared.ID) (time.Time, error) {
    hb, err := s.GetHeartbeat(ctx, agentID)
    if err != nil || hb == nil {
        return time.Time{}, err
    }
    return hb.LastHeartbeat, nil
}
```

### Redis Methods for Offline Detection

```go
// GetAgentsOlderThan returns agent IDs with heartbeat older than cutoff
func (s *AgentStateStore) GetAgentsOlderThan(ctx context.Context, cutoff time.Time) ([]shared.ID, error) {
    // Query sorted set for members with score < cutoff timestamp
    cutoffScore := strconv.FormatFloat(float64(cutoff.Unix()), 'f', 0, 64)

    members, err := s.client.client.ZRangeByScore(ctx, platformAgentOnlineKey, &redis.ZRangeBy{
        Min: "-inf",
        Max: cutoffScore,
    }).Result()

    if err != nil {
        return nil, fmt.Errorf("failed to get stale agents: %w", err)
    }

    result := make([]shared.ID, 0, len(members))
    for _, m := range members {
        id, err := shared.IDFromString(m)
        if err != nil {
            continue
        }
        result = append(result, id)
    }

    return result, nil
}

// MarkAgentOffline removes an agent from the online set
func (s *AgentStateStore) MarkAgentOffline(ctx context.Context, agentID shared.ID) error {
    // Remove from online set
    if err := s.client.client.ZRem(ctx, platformAgentOnlineKey, agentID.String()).Err(); err != nil {
        return fmt.Errorf("failed to remove from online set: %w", err)
    }

    // Delete heartbeat key (optional, will expire anyway)
    heartbeatKey := fmt.Sprintf(agentHeartbeatKey, agentID.String())
    s.client.Del(ctx, heartbeatKey)

    // Delete state key
    stateKey := fmt.Sprintf(platformAgentStatusKey, agentID.String())
    s.client.Del(ctx, stateKey)

    return nil
}
```

## Performance Comparison

### Before Optimization (Current)

| Operation | Per Heartbeat | 100 Agents/min | 1000 Agents/min |
|-----------|---------------|----------------|-----------------|
| DB Read | 1 | 100 | 1000 |
| DB Write | 1 | 100 | 1000 |
| Redis Write | 2 | 200 | 2000 |
| **Total DB ops** | **2** | **200** | **2000** |

### After Optimization (Hybrid)

| Operation | Per Heartbeat | 100 Agents/min | 1000 Agents/min |
|-----------|---------------|----------------|-----------------|
| DB Read | 0 (cached) | ~3 (cache misses) | ~33 (cache misses) |
| DB Write | 0 (hot path) | ~0 | ~0 |
| Redis Read | 2 (config + online check) | 200 | 2000 |
| Redis Write | 2 | 200 | 2000 |
| **Total DB ops** | **0** | **~3** | **~33** |

### State Change DB Operations (Hybrid Addition)

| Event | DB Writes | Frequency |
|-------|-----------|-----------|
| Agent comes online | 1 (`UPDATE last_online_at`) | Once per session |
| Agent goes offline | 1 (`UPDATE last_seen_at, last_offline_at`) | Once per session |
| **Per session** | **2 DB writes** | Regardless of uptime |

### Example: 1000 Agents, 24 Hours

| Scenario | Full DB (Current) | Hybrid (Proposed) |
|----------|-------------------|-------------------|
| Heartbeats (1/min) | 1,440,000 DB writes | 0 DB writes |
| State changes (2/session) | 0 | 2,000 DB writes |
| **Total** | **1,440,000** | **~2,000** |
| **Reduction** | - | **99.86%** |

### Improvement Summary

| Metric | Before | After (Hybrid) | Improvement |
|--------|--------|----------------|-------------|
| DB operations/hour (1000 agents) | 120,000 | ~200 (state changes) | **99.8% reduction** |
| Latency per heartbeat | ~5-10ms | ~1-2ms | **~80% faster** |
| Can query last_online_at? | ❌ No | ✅ Yes | **New capability** |
| Can query last_offline_at? | ❌ No | ✅ Yes | **New capability** |
| Can calculate uptime? | ❌ No | ✅ Yes | **New capability** |

## When Database IS Needed (Hybrid Triggers)

### Trigger Points for Database Updates

| Event | Database Action | Frequency | SQL |
|-------|-----------------|-----------|-----|
| **Agent comes online** | `UPDATE last_online_at` | Once per session | `UPDATE agents SET last_online_at = NOW() WHERE id = $1` |
| **Agent goes offline** | `UPDATE last_seen_at, last_offline_at` | Once per session | `UPDATE agents SET last_seen_at = $2, last_offline_at = NOW() WHERE id = $1` |
| Agent version changes | `UPDATE version` | Rare (agent restart) | `UPDATE agents SET version = $2 WHERE id = $1` |
| Capability drift detected | `UPDATE effective_*` | Rare | Standard update |
| Admin updates agent | Update config fields | Manual action | Standard update |
| Agent deleted | Delete record | Manual action | `DELETE FROM agents WHERE id = $1` |

### Query Examples (Now Possible with Hybrid)

```sql
-- When was agent last online?
SELECT last_online_at, last_offline_at, last_seen_at
FROM agents WHERE id = :agent_id;

-- Result: { last_online_at: "2024-01-15 10:00", last_offline_at: "2024-01-15 18:30", last_seen_at: "2024-01-15 18:29" }

-- All agents that went offline in the last hour
SELECT id, name, last_offline_at
FROM agents
WHERE last_offline_at > NOW() - INTERVAL '1 hour'
ORDER BY last_offline_at DESC;

-- Calculate uptime for each agent (last session)
SELECT
    id,
    name,
    last_online_at,
    last_offline_at,
    EXTRACT(EPOCH FROM (last_offline_at - last_online_at)) / 3600 AS uptime_hours
FROM agents
WHERE last_online_at IS NOT NULL AND last_offline_at IS NOT NULL;

-- Find agents that have been offline for more than 24 hours
SELECT id, name, last_offline_at
FROM agents
WHERE last_offline_at < NOW() - INTERVAL '24 hours'
  AND status = 'active';  -- Still supposed to be active but offline

-- Currently online agents (real-time from Redis, but with historical context)
-- Note: For current online status, query Redis
-- This query shows "last known" info from database
SELECT id, name, last_online_at
FROM agents
WHERE last_online_at > last_offline_at  -- Came online after last going offline
   OR last_offline_at IS NULL;           -- Never went offline
```

## Audit Log Policy for Agents

### Nguyên tắc: Chỉ log events quan trọng, KHÔNG log mỗi heartbeat

**Vấn đề nếu log mỗi heartbeat:**
```
1000 agents × 1 heartbeat/min × 60 min × 24 hours = 1,440,000 audit logs/day
→ Database phình to, queries chậm, storage cost cao
```

### Audit Log Matrix

| Event | Audit Log? | Lý do |
|-------|------------|-------|
| Mỗi heartbeat | ❌ **KHÔNG** | Quá nhiều, không có giá trị debug |
| Agent comes online | ✅ Có | State change quan trọng, debug connection issues |
| Agent goes offline | ✅ Có | State change quan trọng, detect failures |
| Agent error/failure | ✅ Có | Debug, troubleshooting |
| Agent capability drift | ✅ Có | Security concern |
| Agent version change | ✅ Có | Tracking deployments |
| Agent created/deleted | ✅ Có | Admin action audit |

### Audit Log Frequency Comparison

| Approach | Audit Logs/Day (1000 agents) | Storage/Month |
|----------|------------------------------|---------------|
| Log every heartbeat | 1,440,000 | ~50GB |
| Log state changes only | ~2,000-5,000 | ~200MB |
| **Reduction** | **99.7%** | **99.6%** |

### Khi nào cần Audit Log cho Agent?

```go
// ✅ CÓ Audit Log - State transitions và errors
func (s *PlatformAgentService) handleAgentCameOnline(...) {
    s.auditService.LogAgentConnected(...)  // 1 log per session
}

func (m *AgentHealthMonitor) checkAndMarkOfflineAgents(...) {
    s.auditService.LogAgentDisconnected(...)  // 1 log per session
}

func (s *PlatformAgentService) handleHeartbeatError(...) {
    s.auditService.LogAgentError(...)  // Only on errors
}

// ❌ KHÔNG Audit Log - Regular heartbeats
func (s *PlatformAgentService) RecordHeartbeat(...) {
    // Redis operations only
    // NO audit log here - would be 1M+ logs/day
}
```

### Debug Agent Issues Without Audit Logs

Thay vì audit log mỗi heartbeat, sử dụng:

1. **Redis real-time state** - Query current status
2. **Structured logs** - Application logs với log level debug
3. **Metrics/Prometheus** - Heartbeat latency, success rate
4. **last_seen_at in DB** - Khi agent offline

```go
// Debug query: Tìm agents có vấn đề
// Option 1: Redis (real-time)
staleAgents := agentState.GetAgentsOlderThan(ctx, 90*time.Second)

// Option 2: Database (historical)
SELECT id, name, last_seen_at, last_offline_at
FROM agents
WHERE last_offline_at > NOW() - INTERVAL '1 hour'
ORDER BY last_offline_at DESC;

// Option 3: Application logs (detailed debug)
s.logger.Debug("heartbeat received",
    "agent_id", agentID,
    "ip", ip,
    "version", version,
    "current_jobs", currentJobs,
)
```

### Background Sync (Optional)

For reporting/analytics that need historical data:

```go
// BackgroundStatsSyncer syncs aggregated stats to database periodically
type BackgroundStatsSyncer struct {
    agentState *redis.AgentStateStore
    statsRepo  StatsRepository
    interval   time.Duration
}

// Start runs the background sync loop
func (s *BackgroundStatsSyncer) Start(ctx context.Context) {
    ticker := time.NewTicker(s.interval) // e.g., every 5 minutes
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            s.syncStats(ctx)
        }
    }
}

// syncStats aggregates and persists stats
func (s *BackgroundStatsSyncer) syncStats(ctx context.Context) {
    // Get current queue stats from Redis
    queueStats, _ := s.agentState.GetQueueStats(ctx)

    // Get online agent count
    onlineCount, _ := s.agentState.GetOnlinePlatformAgentCount(ctx)

    // Persist aggregated stats for historical analysis
    s.statsRepo.RecordSnapshot(ctx, StatsSnapshot{
        Timestamp:       time.Now(),
        OnlineAgents:    onlineCount,
        TotalQueued:     queueStats.TotalQueued,
        TotalProcessing: queueStats.TotalProcessing,
        AvgWaitTime:     queueStats.AvgWaitTimeSec,
    })
}
```

## Implementation Plan

### Phase 1: Database Schema & Repository ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Add migration for online tracking columns | `migrations/000132_agent_online_tracking.up.sql` | ✅ Done |
| Add UpdateOfflineTimestamp method | `infra/postgres/agent_repository.go` | ✅ Done |
| Add MarkStaleAgentsOffline method | `infra/postgres/agent_repository.go` | ✅ Done |
| Add GetAgentsOfflineSince method | `infra/postgres/agent_repository.go` | ✅ Done |
| Add GetLastHeartbeatTime to Redis | `infra/redis/agent_state.go` | ✅ Done |

**Migration SQL (Simplified - 2 timestamps instead of 3):**
```sql
-- migrations/000132_agent_online_tracking.up.sql
-- Note: last_seen_at already exists, only add last_offline_at
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS last_offline_at TIMESTAMP WITH TIME ZONE;

-- Session tracking tables
CREATE TABLE IF NOT EXISTS agent_sessions (...);
CREATE TABLE IF NOT EXISTS agent_daily_stats (...);
```

### Phase 2: Redis Cache Layer ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Add CachedAgentConfig struct | `infra/redis/agent_state.go` | ✅ Done |
| Add SetAgentConfig/GetAgentConfig | `infra/redis/agent_state.go` | ✅ Done |
| Add InvalidateAgentConfig | `infra/redis/agent_state.go` | ✅ Done |
| Add GetAgentsWithStaleHeartbeat | `infra/redis/agent_state.go` | ✅ Done |
| Add MarkAgentOfflineInCache | `infra/redis/agent_state.go` | ✅ Done |
| Add GetPreviousHealthState/SetPreviousHealthState | `infra/redis/agent_state.go` | ✅ Done |
| Add WasAgentOffline (state transition detection) | `infra/redis/agent_state.go` | ✅ Done |

### Phase 3: Service Layer ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Update RecordHeartbeat (hybrid) | `app/platform_agent_service.go` | ✅ Done |
| Add config caching in heartbeat flow | `app/platform_agent_service.go` | ✅ Done |
| Add state transition detection (WasAgentOffline) | `app/platform_agent_service.go` | ✅ Done |
| Update to use UpdateLastSeen on state transition | `app/platform_agent_service.go` | ✅ Done |

### Phase 4: Health Monitor Worker ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Update AgentHealthController | `infra/controller/agent_health.go` | ✅ Done |
| Use MarkStaleAgentsOffline (with DB update) | `infra/controller/agent_health.go` | ✅ Done |
| Return list of offline agent IDs for audit | `infra/controller/agent_health.go` | ✅ Done |

### Phase 5: Domain Entities & Repositories ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Add AgentSession entity | `domain/agent/entity.go` | ✅ Done |
| Add AgentDailyStats entity | `domain/agent/entity.go` | ✅ Done |
| Add AgentSessionRepository interface | `domain/agent/repository.go` | ✅ Done |
| Add AgentDailyStatsRepository interface | `domain/agent/repository.go` | ✅ Done |
| Implement AgentSessionRepository (Postgres) | `infra/postgres/agent_session_repository.go` | ✅ Done |
| Implement AgentDailyStatsRepository (Postgres) | `infra/postgres/agent_daily_stats_repository.go` | ✅ Done |

### Phase 6: Session Integration ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Create session on agent online | `app/platform_agent_service.go` | ✅ Done |
| End session on agent offline | `infra/controller/agent_health.go` | ✅ Done |
| Wire up session repo in services | `cmd/server/services.go` | ✅ Done |
| Wire up session repo in workers | `cmd/server/workers.go` | ✅ Done |

### Phase 7: Daily Aggregation Worker ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Create AgentStatsAggregator controller | `infra/controller/agent_stats_aggregator.go` | ✅ Done |
| Aggregate sessions into daily stats | `infra/controller/agent_stats_aggregator.go` | ✅ Done |
| Cleanup old sessions (retention) | `infra/controller/agent_stats_aggregator.go` | ✅ Done |
| Cleanup old daily stats (retention) | `infra/controller/agent_stats_aggregator.go` | ✅ Done |
| Register in workers.go | `cmd/server/workers.go` | ✅ Done |

### Phase 8: Analytics API Endpoints ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Create AgentAnalyticsHandler | `infra/http/handler/agent_analytics_handler.go` | ✅ Done |
| ListSessions endpoint | `GET /api/v1/admin/agents/{id}/sessions` | ✅ Done |
| GetActiveSession endpoint | `GET /api/v1/admin/agents/{id}/sessions/active` | ✅ Done |
| GetSessionStats endpoint | `GET /api/v1/admin/agents/{id}/sessions/stats` | ✅ Done |
| ListDailyStats endpoint | `GET /api/v1/admin/agents/{id}/stats` | ✅ Done |
| GetAgentTimeSeries endpoint | `GET /api/v1/admin/agents/{id}/stats/daily` | ✅ Done |
| GetAggregatedStats endpoint | `GET /api/v1/admin/agents/stats/aggregated` | ✅ Done |
| Wire up routes in admin.go | `infra/http/routes/admin.go` | ✅ Done |
| Add handler to Handlers struct | `infra/http/routes/routes.go` | ✅ Done |
| Create handler in handlers.go | `cmd/server/handlers.go` | ✅ Done |

### Phase 8b: Tenant Analytics API Endpoints ✅ COMPLETED

| Task | File | Status |
|------|------|--------|
| Create TenantAgentAnalyticsHandler | `infra/http/handler/tenant_agent_analytics_handler.go` | ✅ Done |
| GetTenantAggregatedStats endpoint | `GET /api/v1/agents/analytics/aggregated` | ✅ Done |
| ListSessions (tenant) endpoint | `GET /api/v1/agents/{id}/analytics/sessions` | ✅ Done |
| GetActiveSession (tenant) endpoint | `GET /api/v1/agents/{id}/analytics/sessions/active` | ✅ Done |
| GetSessionStats (tenant) endpoint | `GET /api/v1/agents/{id}/analytics/stats` | ✅ Done |
| GetTimeSeries (tenant) endpoint | `GET /api/v1/agents/{id}/analytics/daily` | ✅ Done |
| Tenant isolation verification | `verifyAgentTenant()` helper | ✅ Done |
| Wire up routes in scanning.go | `infra/http/routes/scanning.go` | ✅ Done |

### Phase 9: Testing & Validation (Partial)

| Task | File | Status |
|------|------|--------|
| Unit tests for cached config | `infra/redis/agent_state_test.go` | Pending |
| Unit tests for online/offline tracking | `app/platform_agent_service_test.go` | Pending |
| Unit tests for session tracking | `infra/postgres/agent_session_repository_test.go` | ✅ Done |
| Unit tests for daily stats | `infra/postgres/agent_daily_stats_repository_test.go` | ✅ Done |
| Integration tests for hybrid flow | `tests/integration/heartbeat_test.go` | Pending |
| Load testing with 1000 agents | `tests/load/heartbeat_load_test.go` | Pending |
| Verify DB writes only on state change | Metrics dashboard | Pending |

## Monitoring & Alerts

### Key Metrics to Monitor

```go
// Metrics to expose
var (
    heartbeatLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "agent_heartbeat_duration_seconds",
            Help:    "Heartbeat processing duration",
            Buckets: []float64{.001, .005, .01, .025, .05, .1},
        },
        []string{"path"}, // "hot" or "cold"
    )

    configCacheHits = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "agent_config_cache_hits_total",
            Help: "Number of config cache hits",
        },
    )

    configCacheMisses = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "agent_config_cache_misses_total",
            Help: "Number of config cache misses",
        },
    )

    agentsOnline = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "platform_agents_online",
            Help: "Number of online platform agents",
        },
    )
)
```

### Alert Rules

```yaml
groups:
- name: agent_heartbeat
  rules:
  - alert: HighHeartbeatLatency
    expr: histogram_quantile(0.99, rate(agent_heartbeat_duration_seconds_bucket[5m])) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High heartbeat latency detected"

  - alert: LowCacheHitRate
    expr: rate(agent_config_cache_hits_total[5m]) / (rate(agent_config_cache_hits_total[5m]) + rate(agent_config_cache_misses_total[5m])) < 0.9
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Config cache hit rate below 90%"

  - alert: AgentOfflineSpike
    expr: delta(platform_agents_online[5m]) < -10
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "More than 10 agents went offline in 5 minutes"
```

## Summary

### Key Decisions

1. **Hybrid Storage**: Redis for real-time, Database for state transitions only
2. **Online Tracking**: `last_online_at` updated when agent connects (1 write/session)
3. **Offline Tracking**: `last_seen_at` + `last_offline_at` updated when agent disconnects (1 write/session)
4. **Agent config cached in Redis**: 30-minute TTL with invalidation on change
5. **Background worker for offline detection**: Check every 30 seconds, mark offline after 90 seconds

### Hybrid Trade-offs

| Aspect | Redis-Only | Hybrid (Recommended) |
|--------|------------|----------------------|
| DB writes per heartbeat | 0 | 0 |
| DB writes per session | 0 | 2 |
| Query "last online"? | ❌ No | ✅ Yes |
| Query "last offline"? | ❌ No | ✅ Yes |
| Calculate uptime? | ❌ No | ✅ Yes |
| Complexity | Lower | Slightly higher |

### Expected Results

- **99.8%+ reduction** in database operations for heartbeat
- **80%+ faster** heartbeat processing latency
- **New capabilities**: Query last online/offline times, calculate uptime
- **Better scalability** to 1000+ agents without database bottleneck
- **Admin visibility**: Can answer "when did agent X go offline?"

### Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HYBRID HEARTBEAT ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  EVERY HEARTBEAT (60s)                    STATE CHANGES ONLY            │
│  ─────────────────────                    ──────────────────            │
│  Redis: Store heartbeat     ───────►      DB: Update timestamps         │
│  Redis: Update state                                                     │
│  Redis: Update online set                 • Agent comes online:         │
│                                             UPDATE last_online_at        │
│  DB: NOTHING                              • Agent goes offline:          │
│                                             UPDATE last_seen_at,         │
│                                                    last_offline_at       │
│                                                                          │
│  Frequency: 1000 agents = 1000/min        Frequency: ~2 writes/session  │
│  DB Operations: 0                         DB Operations: 2/session       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Analytics API Reference

### Admin Endpoints (Platform Administrators)

These endpoints require Admin API Key authentication via `X-Admin-API-Key` header.

#### List Agent Sessions
```
GET /api/v1/admin/agents/{id}/sessions
```
Returns paginated list of sessions for a specific agent.

**Query Parameters:**
- `page` (int, default: 1) - Page number
- `per_page` (int, default: 20, max: 100) - Items per page

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "agent_id": "uuid",
      "started_at": "2024-01-15T10:00:00Z",
      "ended_at": "2024-01-15T18:30:00Z",
      "duration_seconds": 30600,
      "findings_count": 150,
      "scans_count": 12,
      "errors_count": 2,
      "jobs_completed": 45,
      "version": "1.2.3",
      "hostname": "agent-01.example.com",
      "ip_address": "10.0.0.5",
      "region": "us-east-1"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "total_pages": 8
  }
}
```

#### Get Active Session
```
GET /api/v1/admin/agents/{id}/sessions/active
```
Returns the currently active session for an agent (if any).

**Response (active):**
```json
{
  "id": "uuid",
  "agent_id": "uuid",
  "started_at": "2024-01-15T10:00:00Z",
  "ended_at": null,
  "findings_count": 50,
  ...
}
```

**Response (not active):**
```
HTTP 404 Not Found
```

#### Get Session Statistics
```
GET /api/v1/admin/agents/{id}/sessions/stats
```
Returns aggregate session statistics for an agent.

**Query Parameters:**
- `from` (date, default: 30 days ago) - Start date (YYYY-MM-DD)
- `to` (date, default: today) - End date (YYYY-MM-DD)

**Response:**
```json
{
  "total_sessions": 45,
  "total_duration_seconds": 1382400,
  "total_findings": 5420,
  "total_scans": 180,
  "total_errors": 12,
  "average_session_duration": 30720,
  "average_uptime_percent": 85.5
}
```

#### Get Daily Time Series
```
GET /api/v1/admin/agents/{id}/stats/daily
```
Returns daily statistics time-series for an agent.

**Query Parameters:**
- `from` (date, default: 30 days ago) - Start date (YYYY-MM-DD)
- `to` (date, default: today) - End date (YYYY-MM-DD)

**Response:**
```json
{
  "agent_id": "uuid",
  "from": "2024-01-01",
  "to": "2024-01-30",
  "data": [
    {
      "date": "2024-01-01",
      "total_findings": 120,
      "total_scans": 5,
      "total_errors": 0,
      "total_jobs": 15,
      "online_seconds": 72000,
      "offline_seconds": 14400,
      "session_count": 2
    }
  ]
}
```

#### Get Platform Aggregated Stats
```
GET /api/v1/admin/agents/stats/aggregated
```
Returns platform-wide aggregated statistics across all agents.

**Query Parameters:**
- `from` (date, default: 30 days ago) - Start date (YYYY-MM-DD)
- `to` (date, default: today) - End date (YYYY-MM-DD)

**Response:**
```json
{
  "from": "2024-01-01",
  "to": "2024-01-30",
  "stats": {
    "total_findings": 54200,
    "total_scans": 1800,
    "total_errors": 45,
    "total_jobs": 4500,
    "total_online_seconds": 7200000,
    "total_offline_seconds": 1440000,
    "total_sessions": 450,
    "average_uptime_percent": 83.3,
    "unique_agents": 15
  }
}
```

### Tenant Endpoints (Tenant Users)

These endpoints require JWT authentication and only return data for agents owned by the requesting tenant.

#### Get Tenant Aggregated Stats
```
GET /api/v1/agents/analytics/aggregated
```
Returns aggregated statistics for all agents in the current tenant.

**Response:** Same structure as platform aggregated stats.

#### List Tenant Agent Sessions
```
GET /api/v1/agents/{id}/analytics/sessions
```
Returns paginated list of sessions for a tenant-owned agent.

**Security:** Returns 404 if agent doesn't belong to the requesting tenant.

**Response:** Same structure as admin list sessions.

#### Get Active Session (Tenant)
```
GET /api/v1/agents/{id}/analytics/sessions/active
```
Returns the currently active session with enhanced UX response.

**Response (active):**
```json
{
  "active": true,
  "session": { ... session data ... }
}
```

**Response (not active):**
```json
{
  "active": false,
  "session": null
}
```

#### Get Session Stats (Tenant)
```
GET /api/v1/agents/{id}/analytics/stats
```
Returns aggregate session statistics for a tenant-owned agent.

**Response:** Same structure as admin session stats.

#### Get Daily Time Series (Tenant)
```
GET /api/v1/agents/{id}/analytics/daily
```
Returns daily statistics time-series for a tenant-owned agent.

**Response:** Same structure as admin daily time series.

## Analytics API Security

### Rate Limiting

The analytics endpoints are protected by rate limiting to prevent abuse:

| Endpoint Type | Rate Limit | Key |
|---------------|------------|-----|
| List endpoints (sessions, daily stats) | 60 req/min | Per tenant/user |
| Aggregated stats endpoints | 30 req/min | Per tenant/user |

Rate limiter implementation: `internal/infra/http/middleware/ratelimit.go:AnalyticsRateLimiter`

### Time Range Limits

To prevent expensive queries that could impact database performance:

```go
const MaxTimeRangeDays = 365

// Time ranges are automatically clamped to max 365 days
// If user requests from=2020-01-01 to=2025-01-01 (5 years),
// the API will automatically adjust to from=2024-01-01 to=2025-01-01 (365 days)
```

### Tenant Isolation

Tenant users can only access analytics for agents they own:

```go
// verifyAgentTenant checks ownership before returning data
if agt.TenantID == nil || *agt.TenantID != tenantID {
    // Return 404 to prevent tenant enumeration
    apierror.NotFound("agent").WriteJSON(w)
}
```

### Input Validation

- Agent IDs are validated as UUIDs before database queries
- Pagination is capped at 100 items per page
- Date formats are strictly parsed (YYYY-MM-DD only)

## Related Documents

- [Agent Capability Verification Architecture](./agent-capability-verification.md)
- [Agent Audit Logging Architecture](./agent-audit-logging.md)
- [Platform Security Model](./platform-security.md)
