# Agent Capability Verification Architecture

## Overview

This document describes the **Platform-Controlled with Agent Verification** architecture for managing agent capabilities. This design ensures zero-trust security while maintaining accuracy and admin control.

**Core Principle**: "Platform declares, Agent verifies, Platform enforces"

## Problem Statement

### Current Issues

1. **No validation**: Admin declares capabilities when creating agent, but no verification that agent actually has those capabilities
2. **Static capabilities**: Agent reports capabilities once at registration, no hot-reload when tools are added/removed
3. **Trust gap**: Platform blindly trusts agent's self-reported capabilities
4. **Silent failures**: Jobs dispatched to agents without required tools fail silently

### Scenarios with Problems

| Scenario | Current Behavior | Expected Behavior |
|----------|-----------------|-------------------|
| Admin creates agent with `[sast, sca]`, agent only has `semgrep` | Platform dispatches SCA jobs, they fail | Platform only dispatches SAST jobs |
| Agent installs new tool while running | Platform doesn't know | Platform detects and updates |
| Agent lies about capabilities | Platform trusts, jobs fail | Platform verifies, rejects excess |

## Architecture Design

### Three Capability States

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CAPABILITY STATES                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐    │
│  │   DECLARED   │         │   REPORTED   │         │  EFFECTIVE   │    │
│  │ (by Admin)   │         │  (by Agent)  │         │ (Computed)   │    │
│  │              │         │              │         │              │    │
│  │ Source of    │         │ Actual state │         │ Intersection │    │
│  │ permissions  │         │ from agent   │         │ for dispatch │    │
│  └──────────────┘         └──────────────┘         └──────────────┘    │
│         │                        │                        │             │
│         │                        │                        │             │
│         ▼                        ▼                        ▼             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                  │   │
│  │   EFFECTIVE = INTERSECTION(Declared, Reported)                  │   │
│  │                                                                  │   │
│  │   Security Properties:                                          │   │
│  │   • Agent cannot gain capabilities beyond declared              │   │
│  │   • Jobs only dispatched if agent actually has tools            │   │
│  │   • Drift detection alerts admin to mismatches                  │   │
│  │                                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Model Changes

```go
type Agent struct {
    // ... existing fields ...

    // DECLARED by Admin (source of truth for permissions)
    // What the agent is ALLOWED to do
    DeclaredCapabilities []string  `json:"declared_capabilities"`
    DeclaredTools        []string  `json:"declared_tools"`

    // REPORTED by Agent (actual state)
    // What the agent CLAIMS to have
    ReportedCapabilities []string   `json:"reported_capabilities"`
    ReportedTools        []string   `json:"reported_tools"`
    ReportedToolVersions map[string]string `json:"reported_tool_versions"`
    ReportedAt           *time.Time `json:"reported_at"`

    // EFFECTIVE (computed = intersection)
    // What the agent CAN actually do
    EffectiveCapabilities []string `json:"effective_capabilities"`
    EffectiveTools        []string `json:"effective_tools"`

    // DRIFT DETECTION
    CapabilityDrift *CapabilityDrift `json:"capability_drift,omitempty"`
}

type CapabilityDrift struct {
    // Agent missing capabilities that admin declared
    MissingCapabilities []string `json:"missing_capabilities,omitempty"`
    MissingTools        []string `json:"missing_tools,omitempty"`

    // Agent has extra capabilities not declared by admin (ignored for dispatch)
    ExcessCapabilities []string `json:"excess_capabilities,omitempty"`
    ExcessTools        []string `json:"excess_tools,omitempty"`

    // Drift status
    HasMissing       bool       `json:"has_missing"`
    HasExcess        bool       `json:"has_excess"`
    DetectedAt       time.Time  `json:"detected_at"`

    // Admin acknowledgment
    Acknowledged     bool       `json:"acknowledged"`
    AcknowledgedBy   *string    `json:"acknowledged_by,omitempty"`
    AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
}
```

### Database Schema Changes

```sql
-- Migration: Add capability verification columns to agents table

ALTER TABLE agents
ADD COLUMN declared_capabilities TEXT[] DEFAULT '{}',
ADD COLUMN declared_tools TEXT[] DEFAULT '{}',
ADD COLUMN reported_capabilities TEXT[] DEFAULT '{}',
ADD COLUMN reported_tools TEXT[] DEFAULT '{}',
ADD COLUMN reported_tool_versions JSONB DEFAULT '{}',
ADD COLUMN reported_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN effective_capabilities TEXT[] DEFAULT '{}',
ADD COLUMN effective_tools TEXT[] DEFAULT '{}',
ADD COLUMN capability_drift JSONB;

-- Migrate existing data: declared = current capabilities/tools
UPDATE agents SET
    declared_capabilities = capabilities,
    declared_tools = tools,
    effective_capabilities = capabilities,
    effective_tools = tools;

-- Index for job dispatch queries
CREATE INDEX idx_agents_effective_capabilities ON agents USING GIN (effective_capabilities);
CREATE INDEX idx_agents_effective_tools ON agents USING GIN (effective_tools);

-- Index for drift monitoring
CREATE INDEX idx_agents_capability_drift ON agents ((capability_drift->>'has_missing'))
WHERE capability_drift IS NOT NULL;
```

## Flow Diagrams

### Flow 1: Agent Creation

```
Admin creates agent via UI/API
         │
         ▼
┌─────────────────────────────────────┐
│ POST /api/v1/agents                 │
│ {                                   │
│   "name": "prod-scanner-01",        │
│   "type": "worker",                 │
│   "execution_mode": "daemon",       │
│   "declared_capabilities": [        │
│     "sast", "sca", "secrets"        │
│   ],                                │
│   "declared_tools": [               │
│     "semgrep", "trivy", "gitleaks"  │
│   ]                                 │
│ }                                   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Platform saves agent:               │
│ • declared_* = from request         │
│ • reported_* = empty                │
│ • effective_* = empty               │
│ • status = "pending_verification"   │
│ • Generate API key                  │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Agent cannot receive jobs until     │
│ first heartbeat with capabilities   │
└─────────────────────────────────────┘
```

### Flow 2: Agent Heartbeat with Capability Reporting

```
Agent starts and detects installed tools
         │
         ▼
┌─────────────────────────────────────┐
│ Agent scans for tools:              │
│ • semgrep --version ✓               │
│ • trivy --version ✗ (not found)     │
│ • gitleaks --version ✓              │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ PUT /platform/heartbeat             │
│ {                                   │
│   "reported_capabilities": [        │
│     "sast", "secrets"               │
│   ],                                │
│   "reported_tools": [               │
│     "semgrep", "gitleaks"           │
│   ],                                │
│   "tool_versions": {                │
│     "semgrep": "1.45.0",            │
│     "gitleaks": "8.18.0"            │
│   },                                │
│   "cpu_percent": 25.0,              │
│   "memory_percent": 40.0            │
│ }                                   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Platform processes heartbeat:       │
│                                     │
│ 1. Update reported_* fields         │
│                                     │
│ 2. Compute effective:               │
│    declared = [sast,sca,secrets]    │
│    reported = [sast,secrets]        │
│    effective = [sast,secrets] ✓     │
│                                     │
│ 3. Detect drift:                    │
│    missing = [sca] (no trivy!)      │
│    excess = []                      │
│                                     │
│ 4. Update agent status:             │
│    status = "active"                │
│    health = "online"                │
│                                     │
│ 5. Emit events:                     │
│    • "agent.capability_verified"    │
│    • "agent.capability_drift"       │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Heartbeat Response:                 │
│ {                                   │
│   "expected_capabilities": [        │
│     "sast", "sca", "secrets"        │
│   ],                                │
│   "effective_capabilities": [       │
│     "sast", "secrets"               │
│   ],                                │
│   "missing_tools": ["trivy"]        │
│ }                                   │
└─────────────────────────────────────┘
```

### Flow 3: Job Dispatch

```
Platform needs to dispatch scan job
         │
         ▼
┌─────────────────────────────────────┐
│ Job requirements:                   │
│ • capability: "sca"                 │
│ • tool: "trivy"                     │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Query agents:                       │
│ SELECT * FROM agents                │
│ WHERE status = 'active'             │
│   AND health = 'online'             │
│   AND 'sca' = ANY(effective_caps)   │
│   AND 'trivy' = ANY(effective_tools)│
│ ORDER BY load_score ASC             │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Result for "prod-scanner-01":       │
│ • effective_capabilities =          │
│     [sast, secrets]                 │
│ • "sca" NOT IN effective ❌         │
│ → Agent NOT selected                │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ No agent available for SCA          │
│ → Queue job OR alert admin          │
└─────────────────────────────────────┘
```

### Flow 4: Hot Reload (Tool Added While Running)

```
Admin installs trivy on agent machine
         │
         ▼
┌─────────────────────────────────────┐
│ Agent periodic tool scan            │
│ (every 5 minutes in daemon mode)    │
│                                     │
│ • semgrep --version ✓               │
│ • trivy --version ✓ (NEW!)          │
│ • gitleaks --version ✓              │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Next heartbeat:                     │
│ {                                   │
│   "reported_capabilities": [        │
│     "sast", "sca", "secrets"        │
│   ],                                │
│   "reported_tools": [               │
│     "semgrep", "trivy", "gitleaks"  │
│   ]                                 │
│ }                                   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Platform recalculates:              │
│                                     │
│ declared = [sast,sca,secrets]       │
│ reported = [sast,sca,secrets]       │
│ effective = [sast,sca,secrets] ✓    │
│                                     │
│ drift.missing = [] (resolved!)      │
│                                     │
│ Emit: "agent.capability_drift_resolved"
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Agent can now receive SCA jobs!     │
└─────────────────────────────────────┘
```

## Mismatch Handling Matrix

| Scenario | Detection | Action | Admin Notification |
|----------|-----------|--------|-------------------|
| **Agent missing declared tools** | `missing_tools` not empty | Reduce effective_caps | Warning alert |
| **Agent has extra tools** | `excess_tools` not empty | Ignore (not in effective) | Info alert |
| **Agent never reports** | `reported_at` is null | `effective` = empty | Critical alert |
| **Agent reports invalid caps** | Unknown capability names | Ignore unknown, log warning | Security alert |
| **Drift acknowledged** | `acknowledged` = true | Continue alerting only if drift changes | None |
| **Drift resolved** | `missing` becomes empty | Update effective, clear drift | Info alert |

## Report Ingestion Filtering

### Principle: Only Accept Data for Effective Capabilities

When an agent submits a report (findings, assets, etc.), the platform **MUST** filter the data based on the agent's **effective capabilities**. This prevents:

1. **Unauthorized data injection**: Agent cannot submit DAST findings if only registered for SAST
2. **Data integrity**: Only findings from verified tools are accepted
3. **Audit compliance**: Clear chain of custody for each finding type

### Flow Diagram

```
Agent submits report with findings
         │
         ▼
┌─────────────────────────────────────┐
│ Report contains:                    │
│ • 50 SAST findings (semgrep)        │
│ • 30 DAST findings (nuclei)         │
│ • 20 SCA findings (trivy)           │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Platform checks agent's effective   │
│ capabilities:                       │
│                                     │
│ effective_capabilities = [sast]     │
│ (agent only has semgrep installed)  │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Filter report by effective caps:    │
│                                     │
│ ✓ SAST findings: ACCEPTED (50)      │
│ ✗ DAST findings: REJECTED (30)      │
│ ✗ SCA findings:  REJECTED (20)      │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Response to agent:                  │
│ {                                   │
│   "accepted": 50,                   │
│   "rejected": 50,                   │
│   "rejected_reasons": [             │
│     {                               │
│       "capability": "dast",         │
│       "count": 30,                  │
│       "reason": "not_in_effective"  │
│     },                              │
│     {                               │
│       "capability": "sca",          │
│       "count": 20,                  │
│       "reason": "not_in_effective"  │
│     }                               │
│   ],                                │
│   "warning": "Some findings rejected│
│    due to capability mismatch"      │
│ }                                   │
└─────────────────────────────────────┘
```

### Implementation

```go
// api/internal/app/ingest/capability_filter.go

package ingest

import (
    "context"
    "slices"

    "github.com/exploopio/api/internal/domain/agent"
    "github.com/exploopio/sdk/pkg/eis"
)

// CapabilityFilter filters report data based on agent's effective capabilities
type CapabilityFilter struct {
    logger Logger
}

// FilterResult contains the result of filtering
type FilterResult struct {
    AcceptedFindings  []*eis.Finding
    RejectedFindings  []*eis.Finding
    RejectedByCapability map[string]int // capability -> count rejected
    Warnings          []string
}

// FilterReport filters a report based on agent's effective capabilities
func (f *CapabilityFilter) FilterReport(
    ctx context.Context,
    agent *agent.Agent,
    report *eis.Report,
) (*FilterResult, error) {
    result := &FilterResult{
        RejectedByCapability: make(map[string]int),
    }

    effectiveCaps := agent.EffectiveCapabilities
    if len(effectiveCaps) == 0 {
        // Agent has no effective capabilities - reject all
        result.RejectedFindings = report.Findings
        result.Warnings = append(result.Warnings,
            "All findings rejected: agent has no effective capabilities")
        return result, nil
    }

    for _, finding := range report.Findings {
        // Determine finding's required capability based on type/tool
        requiredCap := f.getRequiredCapability(finding)

        if slices.Contains(effectiveCaps, requiredCap) {
            // Capability is effective - accept finding
            result.AcceptedFindings = append(result.AcceptedFindings, finding)
        } else {
            // Capability not effective - reject finding
            result.RejectedFindings = append(result.RejectedFindings, finding)
            result.RejectedByCapability[requiredCap]++
        }
    }

    // Generate warnings for rejected capabilities
    for cap, count := range result.RejectedByCapability {
        result.Warnings = append(result.Warnings,
            fmt.Sprintf("%d findings rejected: capability '%s' not in agent's effective capabilities",
                count, cap))
    }

    f.logger.Info("report filtered by capabilities",
        "agent_id", agent.ID,
        "effective_caps", effectiveCaps,
        "accepted", len(result.AcceptedFindings),
        "rejected", len(result.RejectedFindings),
        "rejected_by_cap", result.RejectedByCapability,
    )

    return result, nil
}

// getRequiredCapability determines what capability is required for a finding
func (f *CapabilityFilter) getRequiredCapability(finding *eis.Finding) string {
    // Priority 1: Explicit capability in finding metadata
    if finding.Metadata != nil && finding.Metadata.Capability != "" {
        return finding.Metadata.Capability
    }

    // Priority 2: Derive from finding type
    switch finding.Type {
    case eis.FindingTypeSAST, eis.FindingTypeCodeQuality:
        return "sast"
    case eis.FindingTypeSCA, eis.FindingTypeDependency, eis.FindingTypeLicense:
        return "sca"
    case eis.FindingTypeSecret, eis.FindingTypeCredential:
        return "secrets"
    case eis.FindingTypeIaC, eis.FindingTypeMisconfiguration:
        return "iac"
    case eis.FindingTypeDAST, eis.FindingTypeVulnerability:
        return "dast"
    case eis.FindingTypeContainer, eis.FindingTypeImage:
        return "container"
    case eis.FindingTypeInfra, eis.FindingTypeNetwork:
        return "infra"
    case eis.FindingTypeAPI:
        return "api"
    default:
        // Unknown type - use tool name to derive capability
        return f.deriveCapabilityFromTool(finding.Tool)
    }
}

// deriveCapabilityFromTool maps tool names to capabilities
func (f *CapabilityFilter) deriveCapabilityFromTool(tool string) string {
    toolCapabilityMap := map[string]string{
        "semgrep":    "sast",
        "trivy":      "sca",      // Primary capability
        "gitleaks":   "secrets",
        "trufflehog": "secrets",
        "nuclei":     "dast",
        "nmap":       "infra",
        "nikto":      "dast",
        "zap":        "dast",
        "checkov":    "iac",
        "tfsec":      "iac",
    }

    if cap, ok := toolCapabilityMap[strings.ToLower(tool)]; ok {
        return cap
    }

    return "unknown"
}
```

### Integration with Ingest Service

```go
// api/internal/app/ingest/service.go

func (s *IngestService) Ingest(
    ctx context.Context,
    agentID shared.ID,
    input Input,
) (*Output, error) {
    // Get agent with effective capabilities
    agent, err := s.agentRepo.GetByID(ctx, agentID)
    if err != nil {
        return nil, fmt.Errorf("get agent: %w", err)
    }

    // IMPORTANT: Filter report by effective capabilities BEFORE processing
    filterResult, err := s.capabilityFilter.FilterReport(ctx, agent, input.Report)
    if err != nil {
        return nil, fmt.Errorf("filter report: %w", err)
    }

    // Log security event if findings were rejected
    if len(filterResult.RejectedFindings) > 0 {
        s.emitSecurityEvent(ctx, SecurityEvent{
            Type:    SecurityEventUnauthorizedFindings,
            AgentID: agentID,
            Details: map[string]interface{}{
                "rejected_count":  len(filterResult.RejectedFindings),
                "rejected_by_cap": filterResult.RejectedByCapability,
                "effective_caps":  agent.EffectiveCapabilities,
            },
        })
    }

    // Create filtered report with only accepted findings
    filteredReport := &eis.Report{
        Metadata: input.Report.Metadata,
        Assets:   input.Report.Assets,
        Findings: filterResult.AcceptedFindings, // Only accepted findings
    }

    // Process filtered report
    output, err := s.processReport(ctx, agent.TenantID, filteredReport)
    if err != nil {
        return nil, err
    }

    // Add rejection info to output
    output.FindingsRejected = len(filterResult.RejectedFindings)
    output.RejectedByCapability = filterResult.RejectedByCapability
    output.Warnings = append(output.Warnings, filterResult.Warnings...)

    return output, nil
}
```

### API Response Extension

```go
// api/internal/app/ingest/types.go

type Output struct {
    // ... existing fields ...

    // NEW: Capability filtering results
    FindingsRejected     int            `json:"findings_rejected,omitempty"`
    RejectedByCapability map[string]int `json:"rejected_by_capability,omitempty"`
}
```

### Example Scenarios

#### Scenario 1: Agent Tries to Submit Unauthorized Findings

```
Agent: prod-scanner-01
Declared capabilities: [sast, sca]
Effective capabilities: [sast]  (no trivy installed)

Report submitted:
- 100 SAST findings ✓
- 50 SCA findings ✗

Result:
- 100 findings ingested
- 50 findings rejected
- Warning: "50 findings rejected: capability 'sca' not in agent's effective capabilities"
- Security event logged
```

#### Scenario 2: Compromised Agent Tries Data Injection

```
Agent: ci-runner-01
Declared capabilities: [sast]
Effective capabilities: [sast]

Attacker tries to inject:
- 10 fake DAST findings
- 5 fake infra findings

Result:
- All injected findings REJECTED
- Security alert: "Unauthorized findings submission attempt"
- Agent flagged for investigation
```

#### Scenario 3: Normal Operation After Tool Installation

```
Agent: prod-scanner-01
Before: effective = [sast]
After trivy installed: effective = [sast, sca]

Report submitted:
- 100 SAST findings ✓
- 50 SCA findings ✓ (now accepted!)

Result:
- All 150 findings ingested
- No warnings
```

### Configuration

```yaml
# Platform config
ingest:
  capability_filtering:
    enabled: true

    # Strict mode: reject entire report if any finding is unauthorized
    # Lenient mode: accept valid findings, reject invalid ones
    mode: lenient

    # Log security event when findings rejected
    log_rejections: true

    # Alert threshold: alert if more than N findings rejected
    alert_threshold: 10

    # Unknown capability handling
    unknown_capability_action: reject  # or "accept" for permissive mode
```

### Security Considerations

1. **Defense in Depth**: Even if agent reports wrong capabilities, findings are filtered
2. **Audit Trail**: All rejections logged with capability details
3. **No Data Loss**: Rejected findings can be reviewed in security logs
4. **Clear Feedback**: Agent receives detailed rejection reasons

## API Changes

### Heartbeat Request (Agent → Platform)

```go
type HeartbeatInput struct {
    // Existing metrics
    CPUPercent     float64 `json:"cpu_percent"`
    MemoryPercent  float64 `json:"memory_percent"`
    CurrentJobs    int     `json:"current_jobs"`

    // NEW: Capability reporting
    ReportedCapabilities []string          `json:"reported_capabilities,omitempty"`
    ReportedTools        []string          `json:"reported_tools,omitempty"`
    ToolVersions         map[string]string `json:"tool_versions,omitempty"`
}
```

### Heartbeat Response (Platform → Agent)

```go
type HeartbeatResponse struct {
    // Tell agent what platform expects
    ExpectedCapabilities []string `json:"expected_capabilities"`
    ExpectedTools        []string `json:"expected_tools"`

    // What agent can actually do (for agent's reference)
    EffectiveCapabilities []string `json:"effective_capabilities"`
    EffectiveTools        []string `json:"effective_tools"`

    // Drift info for agent logging/alerting
    MissingTools []string `json:"missing_tools,omitempty"`
    Message      string   `json:"message,omitempty"`
}
```

### Agent Response (includes drift info)

```go
type AgentResponse struct {
    ID                    string           `json:"id"`
    Name                  string           `json:"name"`
    Status                string           `json:"status"`
    Health                string           `json:"health"`

    // Three capability states
    DeclaredCapabilities  []string         `json:"declared_capabilities"`
    DeclaredTools         []string         `json:"declared_tools"`
    ReportedCapabilities  []string         `json:"reported_capabilities,omitempty"`
    ReportedTools         []string         `json:"reported_tools,omitempty"`
    EffectiveCapabilities []string         `json:"effective_capabilities"`
    EffectiveTools        []string         `json:"effective_tools"`

    // Drift info
    CapabilityDrift       *CapabilityDrift `json:"capability_drift,omitempty"`

    // ... other fields
}
```

### New Admin Endpoints

```
POST /api/v1/agents/{id}/drift/acknowledge
    Acknowledge drift (stop alerting)

POST /api/v1/agents/{id}/capabilities/sync
    Force re-sync declared from reported (admin chooses to trust agent)

GET /api/v1/agents/drift-report
    List all agents with unacknowledged drift
```

## Agent SDK Changes

### Tool Detection Module

```go
// tools/detector.go

type ToolDetector struct {
    scanInterval time.Duration
    tools        []ToolInfo
    onChange     func([]DetectedTool)
}

type DetectedTool struct {
    Name         string
    Binary       string
    Version      string
    Capabilities []string // e.g., trivy → [sca, container, iac]
    DetectedAt   time.Time
}

func (d *ToolDetector) Start(ctx context.Context) {
    ticker := time.NewTicker(d.scanInterval)
    defer ticker.Stop()

    // Initial scan
    d.scan()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            d.scan()
        }
    }
}

func (d *ToolDetector) scan() {
    var detected []DetectedTool

    for _, tool := range d.tools {
        if version, ok := d.checkTool(tool); ok {
            detected = append(detected, DetectedTool{
                Name:         tool.Name,
                Binary:       tool.Binary,
                Version:      version,
                Capabilities: tool.Capabilities,
                DetectedAt:   time.Now(),
            })
        }
    }

    if d.hasChanged(detected) {
        d.onChange(detected)
    }
}
```

### Heartbeat with Capabilities

```go
// platform/heartbeat.go

func (c *Client) SendHeartbeat(ctx context.Context) (*HeartbeatResponse, error) {
    detected := c.toolDetector.GetDetected()

    req := HeartbeatInput{
        CPUPercent:    c.metrics.CPU(),
        MemoryPercent: c.metrics.Memory(),
        CurrentJobs:   c.jobManager.ActiveCount(),

        // Include detected capabilities
        ReportedCapabilities: c.deriveCapabilities(detected),
        ReportedTools:        c.deriveTools(detected),
        ToolVersions:         c.deriveVersions(detected),
    }

    resp, err := c.api.Heartbeat(ctx, req)
    if err != nil {
        return nil, err
    }

    // Log drift warning if any
    if len(resp.MissingTools) > 0 {
        c.logger.Warn("capability drift detected",
            "missing_tools", resp.MissingTools,
            "message", resp.Message,
        )
    }

    return resp, nil
}
```

## Hot Reload Deep Dive

### Overview

Hot reload cho phép agent detect tools mới được cài đặt mà không cần restart. Đây là tính năng quan trọng cho daemon agents chạy liên tục.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HOT RELOAD ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────┐
                    │    Agent Process    │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Tool Detector │    │ Heartbeat Loop  │    │  Job Executor   │
│               │    │                 │    │                 │
│ • Scan every  │───▶│ • Every 20-60s  │    │ • Uses current  │
│   5 minutes   │    │ • Include caps  │    │   effective     │
│ • Check PATH  │    │ • Get response  │    │   capabilities  │
│ • Run --ver   │    │                 │    │                 │
└───────────────┘    └─────────────────┘    └─────────────────┘
        │                      │
        │   onChange()         │   Heartbeat Response
        ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Capability Cache                          │
│                                                              │
│  detected_tools: [semgrep, trivy, gitleaks]                 │
│  detected_caps:  [sast, sca, secrets, container, iac]       │
│  last_scan:      2024-01-30T10:15:00Z                       │
│  changed:        true                                        │
└─────────────────────────────────────────────────────────────┘
```

### Tool Detection Implementation

```go
// agent/internal/tools/detector.go

package tools

import (
    "context"
    "os/exec"
    "regexp"
    "sync"
    "time"
)

// KnownTools defines all tools the agent can detect
var KnownTools = []ToolDefinition{
    {
        Name:         "semgrep",
        Binary:       "semgrep",
        VersionCmd:   []string{"--version"},
        VersionRegex: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
        Capabilities: []string{"sast"},
    },
    {
        Name:         "trivy",
        Binary:       "trivy",
        VersionCmd:   []string{"--version"},
        VersionRegex: regexp.MustCompile(`Version: (\d+\.\d+\.\d+)`),
        Capabilities: []string{"sca", "container", "iac"},
    },
    {
        Name:         "gitleaks",
        Binary:       "gitleaks",
        VersionCmd:   []string{"version"},
        VersionRegex: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
        Capabilities: []string{"secrets"},
    },
    {
        Name:         "nuclei",
        Binary:       "nuclei",
        VersionCmd:   []string{"-version"},
        VersionRegex: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
        Capabilities: []string{"dast", "infra"},
    },
    {
        Name:         "nmap",
        Binary:       "nmap",
        VersionCmd:   []string{"--version"},
        VersionRegex: regexp.MustCompile(`Nmap version (\d+\.\d+)`),
        Capabilities: []string{"infra", "recon"},
    },
    {
        Name:         "nikto",
        Binary:       "nikto",
        VersionCmd:   []string{"-Version"},
        VersionRegex: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
        Capabilities: []string{"dast"},
    },
    {
        Name:         "zap",
        Binary:       "zap.sh",
        VersionCmd:   []string{"-version"},
        VersionRegex: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
        Capabilities: []string{"dast", "api"},
    },
}

type ToolDefinition struct {
    Name         string
    Binary       string
    VersionCmd   []string
    VersionRegex *regexp.Regexp
    Capabilities []string
}

type DetectedTool struct {
    Name         string    `json:"name"`
    Version      string    `json:"version"`
    Path         string    `json:"path"`
    Capabilities []string  `json:"capabilities"`
    DetectedAt   time.Time `json:"detected_at"`
}

type Detector struct {
    mu           sync.RWMutex
    scanInterval time.Duration
    timeout      time.Duration
    detected     []DetectedTool
    lastScan     time.Time
    onChange     func([]DetectedTool)
    logger       Logger
}

type DetectorConfig struct {
    ScanInterval time.Duration // How often to scan (default: 5m)
    Timeout      time.Duration // Timeout per tool check (default: 5s)
    OnChange     func([]DetectedTool)
}

func NewDetector(cfg DetectorConfig, logger Logger) *Detector {
    if cfg.ScanInterval == 0 {
        cfg.ScanInterval = 5 * time.Minute
    }
    if cfg.Timeout == 0 {
        cfg.Timeout = 5 * time.Second
    }

    return &Detector{
        scanInterval: cfg.ScanInterval,
        timeout:      cfg.Timeout,
        onChange:     cfg.OnChange,
        logger:       logger,
    }
}

// Start begins periodic tool scanning
func (d *Detector) Start(ctx context.Context) {
    // Initial scan immediately
    d.scan(ctx)

    ticker := time.NewTicker(d.scanInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            d.logger.Info("tool detector stopped")
            return
        case <-ticker.C:
            d.scan(ctx)
        }
    }
}

// scan checks all known tools
func (d *Detector) scan(ctx context.Context) {
    d.logger.Debug("starting tool scan")
    start := time.Now()

    var newDetected []DetectedTool
    var wg sync.WaitGroup
    results := make(chan *DetectedTool, len(KnownTools))

    // Scan all tools in parallel
    for _, tool := range KnownTools {
        wg.Add(1)
        go func(t ToolDefinition) {
            defer wg.Done()
            if detected := d.checkTool(ctx, t); detected != nil {
                results <- detected
            }
        }(tool)
    }

    // Wait for all checks to complete
    go func() {
        wg.Wait()
        close(results)
    }()

    // Collect results
    for tool := range results {
        newDetected = append(newDetected, *tool)
    }

    // Check for changes
    changed := d.hasChanged(newDetected)

    // Update state
    d.mu.Lock()
    d.detected = newDetected
    d.lastScan = time.Now()
    d.mu.Unlock()

    d.logger.Info("tool scan complete",
        "duration", time.Since(start),
        "tools_found", len(newDetected),
        "changed", changed,
    )

    // Notify if changed
    if changed && d.onChange != nil {
        d.onChange(newDetected)
    }
}

// checkTool checks if a single tool is installed
func (d *Detector) checkTool(ctx context.Context, tool ToolDefinition) *DetectedTool {
    // Find binary in PATH
    path, err := exec.LookPath(tool.Binary)
    if err != nil {
        return nil // Not installed
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(ctx, d.timeout)
    defer cancel()

    // Run version command
    cmd := exec.CommandContext(ctx, tool.Binary, tool.VersionCmd...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        d.logger.Debug("tool version check failed",
            "tool", tool.Name,
            "error", err,
        )
        // Tool exists but version check failed - still report it
        return &DetectedTool{
            Name:         tool.Name,
            Version:      "unknown",
            Path:         path,
            Capabilities: tool.Capabilities,
            DetectedAt:   time.Now(),
        }
    }

    // Extract version
    version := "unknown"
    if matches := tool.VersionRegex.FindStringSubmatch(string(output)); len(matches) > 1 {
        version = matches[1]
    }

    return &DetectedTool{
        Name:         tool.Name,
        Version:      version,
        Path:         path,
        Capabilities: tool.Capabilities,
        DetectedAt:   time.Now(),
    }
}

// hasChanged compares new detection with previous
func (d *Detector) hasChanged(newDetected []DetectedTool) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()

    if len(d.detected) != len(newDetected) {
        return true
    }

    // Create map of old tools
    oldTools := make(map[string]string)
    for _, t := range d.detected {
        oldTools[t.Name] = t.Version
    }

    // Check for differences
    for _, t := range newDetected {
        if oldVer, exists := oldTools[t.Name]; !exists || oldVer != t.Version {
            return true
        }
    }

    return false
}

// GetDetected returns current detected tools (thread-safe)
func (d *Detector) GetDetected() []DetectedTool {
    d.mu.RLock()
    defer d.mu.RUnlock()

    result := make([]DetectedTool, len(d.detected))
    copy(result, d.detected)
    return result
}

// GetCapabilities derives capabilities from detected tools
func (d *Detector) GetCapabilities() []string {
    d.mu.RLock()
    defer d.mu.RUnlock()

    capSet := make(map[string]bool)
    for _, tool := range d.detected {
        for _, cap := range tool.Capabilities {
            capSet[cap] = true
        }
    }

    caps := make([]string, 0, len(capSet))
    for cap := range capSet {
        caps = append(caps, cap)
    }
    return caps
}

// GetTools returns list of detected tool names
func (d *Detector) GetTools() []string {
    d.mu.RLock()
    defer d.mu.RUnlock()

    tools := make([]string, len(d.detected))
    for i, t := range d.detected {
        tools[i] = t.Name
    }
    return tools
}

// GetToolVersions returns map of tool name to version
func (d *Detector) GetToolVersions() map[string]string {
    d.mu.RLock()
    defer d.mu.RUnlock()

    versions := make(map[string]string)
    for _, t := range d.detected {
        versions[t.Name] = t.Version
    }
    return versions
}

// ForceScan triggers an immediate scan (useful after tool installation)
func (d *Detector) ForceScan(ctx context.Context) {
    d.scan(ctx)
}
```

### Integration with Agent

```go
// agent/internal/platform/agent.go

type PlatformAgent struct {
    // ... existing fields ...

    toolDetector *tools.Detector
    capabilityMu sync.RWMutex
    lastReported struct {
        capabilities []string
        tools        []string
        versions     map[string]string
    }
}

func NewPlatformAgent(cfg Config) (*PlatformAgent, error) {
    agent := &PlatformAgent{
        // ... existing init ...
    }

    // Initialize tool detector with change callback
    agent.toolDetector = tools.NewDetector(tools.DetectorConfig{
        ScanInterval: cfg.ToolScanInterval, // default 5m
        Timeout:      cfg.ToolCheckTimeout, // default 5s
        OnChange: func(detected []tools.DetectedTool) {
            agent.onToolsChanged(detected)
        },
    }, agent.logger)

    return agent, nil
}

func (a *PlatformAgent) Start(ctx context.Context) error {
    // Start tool detector in background
    go a.toolDetector.Start(ctx)

    // Start heartbeat loop
    go a.heartbeatLoop(ctx)

    // Start job poller
    go a.jobPoller.Start(ctx)

    // ... rest of startup ...
}

// onToolsChanged is called when tool detector finds changes
func (a *PlatformAgent) onToolsChanged(detected []tools.DetectedTool) {
    a.logger.Info("tool changes detected",
        "tools", len(detected),
    )

    // Update cached values
    a.capabilityMu.Lock()
    a.lastReported.capabilities = a.toolDetector.GetCapabilities()
    a.lastReported.tools = a.toolDetector.GetTools()
    a.lastReported.versions = a.toolDetector.GetToolVersions()
    a.capabilityMu.Unlock()

    // Trigger immediate heartbeat to notify platform
    // (optional: could wait for next scheduled heartbeat)
    go a.sendHeartbeatWithCapabilities(context.Background())
}

func (a *PlatformAgent) sendHeartbeatWithCapabilities(ctx context.Context) error {
    a.capabilityMu.RLock()
    caps := a.lastReported.capabilities
    tools := a.lastReported.tools
    versions := a.lastReported.versions
    a.capabilityMu.RUnlock()

    req := &HeartbeatRequest{
        // Standard metrics
        CPUPercent:    a.metrics.CPU(),
        MemoryPercent: a.metrics.Memory(),
        CurrentJobs:   a.jobManager.ActiveCount(),
        MaxJobs:       a.config.MaxConcurrentJobs,

        // Capability report
        ReportedCapabilities: caps,
        ReportedTools:        tools,
        ToolVersions:         versions,
    }

    resp, err := a.api.SendHeartbeat(ctx, req)
    if err != nil {
        return err
    }

    // Handle drift warning from platform
    if len(resp.MissingTools) > 0 {
        a.logger.Warn("capability drift detected by platform",
            "expected_tools", resp.ExpectedTools,
            "missing_tools", resp.MissingTools,
            "effective_capabilities", resp.EffectiveCapabilities,
        )
    }

    return nil
}
```

### Platform Side Processing

```go
// api/internal/app/platform_agent_service.go

func (s *PlatformAgentService) RecordHeartbeat(
    ctx context.Context,
    agentID shared.ID,
    input HeartbeatInput,
) (*HeartbeatResponse, error) {
    agent, err := s.repo.GetByID(ctx, agentID)
    if err != nil {
        return nil, err
    }

    // Update standard metrics
    agent.UpdateExtendedMetrics(agent.ExtendedMetrics{
        CPUPercent:    input.CPUPercent,
        MemoryPercent: input.MemoryPercent,
        // ...
    })
    agent.UpdateLastSeen()

    // Process capability report if present
    var driftChanged bool
    if len(input.ReportedCapabilities) > 0 || len(input.ReportedTools) > 0 {
        driftChanged = s.processCapabilityReport(ctx, agent, input)
    }

    // Persist changes
    if err := s.repo.Update(ctx, agent); err != nil {
        return nil, err
    }

    // Emit events if drift changed
    if driftChanged {
        s.emitDriftEvent(ctx, agent)
    }

    // Build response
    return &HeartbeatResponse{
        ExpectedCapabilities:  agent.DeclaredCapabilities,
        ExpectedTools:         agent.DeclaredTools,
        EffectiveCapabilities: agent.EffectiveCapabilities,
        EffectiveTools:        agent.EffectiveTools,
        MissingTools:          agent.GetMissingTools(),
    }, nil
}

func (s *PlatformAgentService) processCapabilityReport(
    ctx context.Context,
    agent *agent.Agent,
    input HeartbeatInput,
) bool {
    // Update reported values
    oldReported := agent.ReportedCapabilities
    agent.ReportedCapabilities = s.filterKnownCapabilities(input.ReportedCapabilities)
    agent.ReportedTools = s.filterKnownTools(input.ReportedTools)
    agent.ReportedToolVersions = input.ToolVersions
    agent.ReportedAt = timePtr(time.Now())

    // Compute effective = intersection(declared, reported)
    agent.EffectiveCapabilities = intersection(
        agent.DeclaredCapabilities,
        agent.ReportedCapabilities,
    )
    agent.EffectiveTools = intersection(
        agent.DeclaredTools,
        agent.ReportedTools,
    )

    // Compute drift
    newDrift := s.computeDrift(agent)
    oldDrift := agent.CapabilityDrift

    // Check if drift changed
    driftChanged := !driftEqual(oldDrift, newDrift)

    // Update drift
    agent.CapabilityDrift = newDrift

    // Update status if first report
    if len(oldReported) == 0 && agent.Status == AgentStatusPendingVerification {
        agent.Status = AgentStatusActive
    }

    s.logger.Info("capability report processed",
        "agent_id", agent.ID,
        "declared_caps", agent.DeclaredCapabilities,
        "reported_caps", agent.ReportedCapabilities,
        "effective_caps", agent.EffectiveCapabilities,
        "has_drift", newDrift != nil && newDrift.HasMissing,
    )

    return driftChanged
}

func (s *PlatformAgentService) computeDrift(agent *agent.Agent) *agent.CapabilityDrift {
    missing := difference(agent.DeclaredCapabilities, agent.ReportedCapabilities)
    missingTools := difference(agent.DeclaredTools, agent.ReportedTools)
    excess := difference(agent.ReportedCapabilities, agent.DeclaredCapabilities)
    excessTools := difference(agent.ReportedTools, agent.DeclaredTools)

    if len(missing) == 0 && len(missingTools) == 0 &&
       len(excess) == 0 && len(excessTools) == 0 {
        return nil // No drift
    }

    return &agent.CapabilityDrift{
        MissingCapabilities: missing,
        MissingTools:        missingTools,
        ExcessCapabilities:  excess,
        ExcessTools:         excessTools,
        HasMissing:          len(missing) > 0 || len(missingTools) > 0,
        HasExcess:           len(excess) > 0 || len(excessTools) > 0,
        DetectedAt:          time.Now(),
    }
}

// Helper functions
func intersection(a, b []string) []string {
    set := make(map[string]bool)
    for _, v := range a {
        set[v] = true
    }

    var result []string
    for _, v := range b {
        if set[v] {
            result = append(result, v)
        }
    }
    return result
}

func difference(a, b []string) []string {
    set := make(map[string]bool)
    for _, v := range b {
        set[v] = true
    }

    var result []string
    for _, v := range a {
        if !set[v] {
            result = append(result, v)
        }
    }
    return result
}
```

### Hot Reload Scenarios

#### Scenario 1: New Tool Installed

```
Timeline:
─────────────────────────────────────────────────────────────────────────
T=0    Admin declares: [sast, sca, secrets]
       Agent reports:  [sast, secrets]      (no trivy)
       Effective:      [sast, secrets]
       Drift:          missing=[sca], missing_tools=[trivy]
─────────────────────────────────────────────────────────────────────────
T=10m  Admin installs trivy on agent machine
       (Agent doesn't know yet)
─────────────────────────────────────────────────────────────────────────
T=15m  Tool Detector runs periodic scan
       → Finds trivy v0.48.0
       → onChange() triggered
       → Immediate heartbeat sent
─────────────────────────────────────────────────────────────────────────
T=15m  Platform processes heartbeat:
       Agent reports:  [sast, sca, secrets]  (now has trivy!)
       Effective:      [sast, sca, secrets]  ← UPDATED
       Drift:          null                   (resolved!)

       Event emitted: "agent.capability_drift_resolved"
─────────────────────────────────────────────────────────────────────────
T=15m+ Agent can now receive SCA jobs!
```

#### Scenario 2: Tool Removed

```
Timeline:
─────────────────────────────────────────────────────────────────────────
T=0    Agent has:     [semgrep, trivy, gitleaks]
       Effective:     [sast, sca, secrets]
─────────────────────────────────────────────────────────────────────────
T=5m   Admin removes trivy (apt remove trivy)
       (Agent doesn't know yet)
─────────────────────────────────────────────────────────────────────────
T=10m  Tool Detector runs periodic scan
       → trivy not found
       → onChange() triggered
       → Heartbeat sent
─────────────────────────────────────────────────────────────────────────
T=10m  Platform processes heartbeat:
       Agent reports:  [sast, secrets]       (no sca!)
       Effective:      [sast, secrets]       ← REDUCED
       Drift:          missing=[sca]

       Event emitted: "agent.capability_drift"
       Alert sent to admin
─────────────────────────────────────────────────────────────────────────
T=10m+ Agent no longer receives SCA jobs
       Jobs in queue for SCA → routed to other agents
```

#### Scenario 3: Tool Version Update

```
Timeline:
─────────────────────────────────────────────────────────────────────────
T=0    semgrep v1.44.0 installed
─────────────────────────────────────────────────────────────────────────
T=30m  Admin upgrades: semgrep v1.45.0
─────────────────────────────────────────────────────────────────────────
T=35m  Tool Detector runs scan
       → semgrep version changed: 1.44.0 → 1.45.0
       → onChange() triggered (version change counts as change)
       → Heartbeat with new version sent
─────────────────────────────────────────────────────────────────────────
T=35m  Platform updates tool_versions
       → No drift (capabilities same)
       → Version info logged for audit
```

### Configuration Options

```yaml
# Agent config (agent side)
agent:
  tool_detection:
    # How often to scan for tools
    scan_interval: 5m

    # Timeout for each tool's version check
    check_timeout: 5s

    # Whether to trigger immediate heartbeat on change
    notify_on_change: true

    # Additional paths to search for tools (beyond PATH)
    extra_paths:
      - /opt/security-tools/bin
      - /usr/local/bin

    # Custom tools (beyond built-in KnownTools)
    custom_tools:
      - name: my-scanner
        binary: my-scanner
        version_cmd: ["--version"]
        version_regex: "v(\\d+\\.\\d+\\.\\d+)"
        capabilities: ["custom"]

# Platform config (server side)
platform:
  capability_verification:
    # How long to wait for first capability report
    verification_timeout: 10m

    # Auto-acknowledge drift for matching patterns
    auto_acknowledge_patterns:
      - "excess_only"  # Auto-ack if only excess (agent has more than declared)

    # Drift alert cooldown (don't spam alerts)
    alert_cooldown: 1h
```

### Edge Cases

| Case | Behavior |
|------|----------|
| Tool check times out | Tool reported with version="unknown", capabilities still counted |
| Tool binary exists but crashes | Same as timeout - still reported |
| Multiple versions installed | First found in PATH wins |
| Tool requires license/activation | Version check may fail, reported as unknown |
| Container with read-only fs | Works fine - only reads, no writes |
| Network tools needing sudo | Agent should run with appropriate permissions |

## Execution Mode Verification

### Problem: Mode Mismatch Attack

Một agent được tạo với `execution_mode: daemon` có thể bị sử dụng sai:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EXECUTION MODE MISMATCH ATTACK                       │
└─────────────────────────────────────────────────────────────────────────┘

Admin creates:                     Attacker/Misconfiguration:
┌─────────────────────┐            ┌─────────────────────┐
│ Agent: prod-daemon  │            │ Uses same API key   │
│ Mode: daemon        │───────────▶│ Runs as: runner     │
│ API Key: exp-ak-xxx │            │ In CI/CD pipeline   │
└─────────────────────┘            └─────────────────────┘
                                            │
                                            ▼
                                   ┌─────────────────────┐
                                   │ Problems:           │
                                   │ • No lease renewal  │
                                   │ • No heartbeat loop │
                                   │ • Jobs not polled   │
                                   │ • Metrics wrong     │
                                   │ • Audit confusing   │
                                   └─────────────────────┘
```

### Solution: Execution Mode Verification

#### Data Model Addition

```go
type Agent struct {
    // ... existing fields ...

    // DECLARED execution mode (by Admin)
    DeclaredExecutionMode ExecutionMode `json:"declared_execution_mode"`

    // REPORTED execution mode (by Agent in heartbeat)
    ReportedExecutionMode ExecutionMode `json:"reported_execution_mode,omitempty"`

    // Execution mode drift
    ExecutionModeMismatch bool `json:"execution_mode_mismatch,omitempty"`
}
```

#### Heartbeat Extension

```go
type HeartbeatInput struct {
    // ... existing fields ...

    // Agent reports its actual execution mode
    ExecutionMode ExecutionMode `json:"execution_mode"`

    // For daemon mode: lease info
    LeaseID          string `json:"lease_id,omitempty"`
    LeaseDurationSec int    `json:"lease_duration_sec,omitempty"`

    // For runner mode: job context
    JobID     string `json:"job_id,omitempty"`
    IsOneShot bool   `json:"is_one_shot,omitempty"`
}
```

#### Verification Logic

```go
func (s *PlatformAgentService) verifyExecutionMode(
    ctx context.Context,
    agent *agent.Agent,
    input HeartbeatInput,
) error {
    // Update reported mode
    agent.ReportedExecutionMode = input.ExecutionMode

    // Check for mismatch
    if agent.DeclaredExecutionMode != input.ExecutionMode {
        agent.ExecutionModeMismatch = true

        s.logger.Warn("execution mode mismatch detected",
            "agent_id", agent.ID,
            "declared_mode", agent.DeclaredExecutionMode,
            "reported_mode", input.ExecutionMode,
        )

        // Emit security event
        s.emitSecurityEvent(ctx, SecurityEvent{
            Type:    SecurityEventExecutionModeMismatch,
            AgentID: agent.ID,
            Details: map[string]interface{}{
                "declared_mode": agent.DeclaredExecutionMode,
                "reported_mode": input.ExecutionMode,
            },
        })

        // Determine action based on policy
        switch s.config.ExecutionModeMismatchPolicy {
        case PolicyWarn:
            // Log and continue
            return nil

        case PolicyReject:
            // Reject heartbeat, agent cannot operate
            return ErrExecutionModeMismatch

        case PolicyAdapt:
            // Auto-adapt effective mode to reported
            // (requires admin approval for security)
            return nil
        }
    }

    agent.ExecutionModeMismatch = false
    return nil
}
```

#### Policy Options

```yaml
platform:
  execution_mode_verification:
    # Policy when mode mismatch detected
    # - warn: Log warning, allow operation
    # - reject: Reject heartbeat, block agent
    # - adapt: Auto-adapt (not recommended for security)
    mismatch_policy: reject

    # Grace period for first heartbeat (allow mode detection)
    grace_period: 30s

    # Actions for specific mismatches
    mismatch_actions:
      daemon_as_runner:
        action: reject
        alert: critical
        message: "Daemon agent running as one-shot runner"

      runner_as_daemon:
        action: warn
        alert: warning
        message: "Runner agent trying to run as daemon"
```

#### Behavioral Differences to Detect

| Behavior | Daemon Mode | Runner Mode |
|----------|-------------|-------------|
| **Lease renewal** | Every 20-30s | None or once |
| **Heartbeat frequency** | Regular (30-60s) | Once at start, once at end |
| **Job polling** | Continuous long-poll | None (job pushed) |
| **Lifetime** | Hours/Days | Minutes |
| **Concurrent jobs** | Multiple | Usually 1 |
| **Graceful shutdown** | Coordinated | Immediate exit |

#### Detection Heuristics

```go
type ExecutionModeDetector struct {
    heartbeatHistory []HeartbeatRecord
    windowSize       time.Duration // e.g., 5 minutes
}

func (d *ExecutionModeDetector) DetectActualMode(agentID string) ExecutionMode {
    records := d.getRecentHeartbeats(agentID, d.windowSize)

    if len(records) == 0 {
        return ExecutionModeUnknown
    }

    // Heuristic 1: Heartbeat frequency
    avgInterval := d.calculateAverageInterval(records)
    if avgInterval > 2*time.Minute {
        // Infrequent heartbeats = likely runner
        return ExecutionModeStandalone
    }

    // Heuristic 2: Lease presence
    hasLease := records[len(records)-1].LeaseID != ""
    if !hasLease {
        return ExecutionModeStandalone
    }

    // Heuristic 3: Job pattern
    if d.hasPollingPattern(records) {
        return ExecutionModeDaemon
    }

    // Heuristic 4: Lifetime
    firstSeen := records[0].Timestamp
    if time.Since(firstSeen) > 10*time.Minute && len(records) > 5 {
        return ExecutionModeDaemon
    }

    return ExecutionModeStandalone
}
```

#### API Response with Mode Info

```go
type HeartbeatResponse struct {
    // ... existing fields ...

    // Execution mode verification result
    DeclaredExecutionMode ExecutionMode `json:"declared_execution_mode"`
    ExecutionModeMatch    bool          `json:"execution_mode_match"`
    ModeWarning           string        `json:"mode_warning,omitempty"`
}
```

#### Agent-Side Handling

```go
// Agent should report its actual mode
func (a *Agent) SendHeartbeat(ctx context.Context) (*HeartbeatResponse, error) {
    req := HeartbeatInput{
        // ... other fields ...

        ExecutionMode: a.config.ExecutionMode, // "daemon" or "standalone"
        IsOneShot:     a.config.ExecutionMode == ExecutionModeStandalone,
    }

    if a.config.ExecutionMode == ExecutionModeDaemon {
        req.LeaseID = a.leaseManager.CurrentLeaseID()
        req.LeaseDurationSec = int(a.leaseManager.LeaseDuration().Seconds())
    }

    resp, err := a.api.Heartbeat(ctx, req)
    if err != nil {
        return nil, err
    }

    // Handle mode mismatch warning
    if !resp.ExecutionModeMatch {
        a.logger.Error("execution mode mismatch",
            "declared", resp.DeclaredExecutionMode,
            "actual", a.config.ExecutionMode,
            "warning", resp.ModeWarning,
        )

        // Optionally exit if policy is strict
        if a.config.ExitOnModeMismatch {
            return nil, ErrExecutionModeMismatch
        }
    }

    return resp, nil
}
```

### Mismatch Scenarios

#### Scenario 1: Daemon Key Used as Runner (Critical)

```
Timeline:
─────────────────────────────────────────────────────────────────────────
T=0    Attacker gets daemon agent's API key
       Runs: agent -standalone -api-key exp-ak-xxxx -tool semgrep

T=1s   Agent sends heartbeat:
       {
         "execution_mode": "standalone",
         "is_one_shot": true,
         "lease_id": ""  // No lease!
       }

T=1s   Platform detects mismatch:
       declared_mode = "daemon"
       reported_mode = "standalone"
       → Policy: REJECT
       → Response: 403 Forbidden "Execution mode mismatch"
       → Security event emitted
       → Admin alerted
─────────────────────────────────────────────────────────────────────────
Result: Attack blocked, agent cannot operate
```

#### Scenario 2: Runner Key Used as Daemon (Medium)

```
Timeline:
─────────────────────────────────────────────────────────────────────────
T=0    Someone misconfigures: runs runner agent in daemon mode
       Runs: agent -daemon -api-key exp-ak-yyyy

T=1s   Agent sends heartbeat:
       {
         "execution_mode": "daemon",
         "lease_id": "lease-123"
       }

T=1s   Platform detects mismatch:
       declared_mode = "standalone"
       reported_mode = "daemon"
       → Policy: WARN (less severe than reverse)
       → Response: 200 OK with warning
       → Admin notified
─────────────────────────────────────────────────────────────────────────
Result: Allowed with warning (runner trying to be daemon is less dangerous)
```

### Database Schema Addition

```sql
ALTER TABLE agents
ADD COLUMN declared_execution_mode TEXT NOT NULL DEFAULT 'standalone',
ADD COLUMN reported_execution_mode TEXT,
ADD COLUMN execution_mode_mismatch BOOLEAN DEFAULT FALSE,
ADD COLUMN execution_mode_mismatch_at TIMESTAMP WITH TIME ZONE;

-- Index for security monitoring
CREATE INDEX idx_agents_execution_mode_mismatch
ON agents (execution_mode_mismatch)
WHERE execution_mode_mismatch = TRUE;
```

### Admin UI Indicators

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Agent: prod-daemon-01                                          [Active] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ Execution Mode:                                                          │
│ ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   │
│ │  Declared   │    │  Reported   │    │   Status    │                   │
│ │   daemon    │ ≠  │ standalone  │ →  │ ⚠️ MISMATCH │                   │
│ └─────────────┘    └─────────────┘    └─────────────┘                   │
│                                                                          │
│ ⚠️ Security Alert: This agent was configured as daemon but is running   │
│    as standalone. This may indicate misconfiguration or compromise.      │
│                                                                          │
│ Actions:                                                                 │
│ [Investigate] [Block Agent] [Regenerate Key] [Acknowledge]              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Zero-Trust Model

1. **Agent cannot escalate privileges**: Even if agent reports more capabilities than declared, effective = intersection means agent cannot gain more power

2. **Platform controls permissions**: Admin declares what agent is ALLOWED to do, not what it claims to do

3. **Verification required**: Agent must verify capabilities via heartbeat before receiving jobs

4. **Audit trail**: All capability changes logged with timestamps

### Attack Vectors Mitigated

| Attack | Mitigation |
|--------|------------|
| Agent lies about capabilities | Effective = min(declared, reported) |
| Agent tries to receive unauthorized jobs | Query uses effective, not declared |
| Malicious agent registration | Bootstrap token constraints still apply |
| Capability injection via heartbeat | Only known capabilities accepted |
| **Agent submits unauthorized findings** | **Report filtered by effective capabilities** |
| **Data injection via compromised agent** | **Only findings matching effective caps accepted** |

## Implementation Plan

### Phase 1: Database & Domain (Week 1)

1. Add migration for new columns
2. Update Agent entity with new fields
3. Add CapabilityDrift value object
4. Update repository methods

### Phase 2: Heartbeat Changes (Week 1)

1. Extend HeartbeatInput with capability fields
2. Add capability verification logic in service
3. Compute effective capabilities on heartbeat
4. Add HeartbeatResponse with drift info

### Phase 3: Job Dispatch Changes (Week 2)

1. Update agent selection queries to use effective_*
2. Add "pending_verification" status handling
3. Update agent scoring to consider effective caps

### Phase 4: Agent SDK Changes (Week 2)

1. Add ToolDetector module
2. Update heartbeat to include capabilities
3. Add periodic tool scanning (hot reload)
4. Handle HeartbeatResponse drift warnings

### Phase 5: Admin UI & Alerts (Week 3)

1. Add drift indicators in agent list
2. Add drift acknowledgment UI
3. Add drift notifications (webhook, email)
4. Add drift report endpoint

### Phase 6: Testing & Rollout (Week 3)

1. Unit tests for capability verification
2. Integration tests for full flow
3. Load tests for heartbeat performance
4. Gradual rollout with feature flag

## Configuration

```yaml
# Agent capability verification config
agent_capability:
  # How often agent scans for tools (daemon mode)
  tool_scan_interval: 5m

  # Grace period before marking agent as "pending_verification"
  verification_grace_period: 2m

  # Enable/disable drift alerting
  drift_alerting_enabled: true

  # Alert channels
  drift_alert_channels:
    - webhook
    - email

  # Known capabilities (for validation)
  known_capabilities:
    - sast
    - sca
    - secrets
    - iac
    - dast
    - container
    - infra
    - api
    - web3
    - collector

  # Tool to capability mapping
  tool_capabilities:
    semgrep: [sast]
    trivy: [sca, container, iac]
    gitleaks: [secrets]
    nuclei: [dast, infra]
    nmap: [infra]
    nikto: [dast]
```

## Backward Compatibility

### Migration Strategy

1. **Existing agents**: `declared` = current `capabilities`, `effective` = `declared`
2. **First heartbeat**: Populates `reported`, recalculates `effective`
3. **No breaking changes**: Old agents continue working until first heartbeat
4. **Gradual adoption**: New fields optional, old API still works

### API Versioning

- v1 API: Returns `capabilities` (= effective for backward compat)
- v2 API: Returns all three states (declared, reported, effective)

## Metrics & Observability

### Metrics

```
# Drift detection
agent_capability_drift_total{agent_id, drift_type}
agent_capability_drift_resolved_total{agent_id}

# Verification
agent_capability_verification_latency_seconds
agent_capability_verification_failures_total

# Tool detection
agent_tool_detection_duration_seconds
agent_tools_detected_total{agent_id}
```

### Alerts

```yaml
alerts:
  - name: AgentCapabilityDriftCritical
    condition: drift.has_missing AND NOT drift.acknowledged
    severity: warning
    message: "Agent {{agent_name}} missing tools: {{missing_tools}}"

  - name: AgentNeverVerified
    condition: status = 'pending_verification' AND age > 10m
    severity: critical
    message: "Agent {{agent_name}} never sent capability report"
```

## FAQ

**Q: What happens if agent never sends capabilities in heartbeat?**
A: Agent stays in "pending_verification" status, effective = empty, cannot receive jobs.

**Q: Can admin force-enable capabilities without agent verification?**
A: No. This would defeat zero-trust. Admin can only declare, agent must verify.

**Q: What if tool detection is slow?**
A: Tool detection runs async. Heartbeat uses cached results. First heartbeat may have empty reported, subsequent ones will be accurate.

**Q: How to handle ephemeral CI/CD runners?**
A: For runners (standalone mode), capabilities are reported once at startup. No hot-reload needed since runner exits after job.

**Q: What about container-based agents with fixed tools?**
A: Same logic applies. Container starts → detects tools → reports in heartbeat. Effective caps calculated immediately.

---

## Comprehensive Review & Improvements

> **Note**: This section was added after comprehensive review from PM/TechLead/BA, Security Expert, and Database optimization perspectives.

### User Stories & Acceptance Criteria

#### US1: Admin Views Capability Drift
```
As an Admin,
I want to see which agents have capability drift
So that I can take corrective action

Acceptance Criteria:
- Given an agent missing declared tools
- When I view the agent list
- Then I see a warning indicator for that agent
- And I can see exactly which tools are missing
```

#### US2: Platform Prevents Invalid Job Dispatch
```
As the Platform,
I want to reject jobs to agents missing required tools
So that jobs don't fail silently

Acceptance Criteria:
- Given agent "scanner-01" missing trivy tool
- When SCA job requires trivy
- Then job is NOT assigned to "scanner-01"
- And job is queued for other capable agents OR admin is alerted
```

#### US3: Agent Hot Reloads New Tools
```
As an Agent (daemon mode),
I want to detect newly installed tools without restart
So that I can receive new job types immediately

Acceptance Criteria:
- Given agent running without trivy
- When admin installs trivy on agent machine
- Then within 5 minutes agent detects trivy
- And next heartbeat reports new capability
- And platform updates effective capabilities
```

#### US4: Security Team Monitors Mode Mismatch
```
As a Security Team member,
I want to be alerted when execution mode mismatch detected
So that I can investigate potential security incidents

Acceptance Criteria:
- Given agent configured as "daemon"
- When agent connects as "standalone"
- Then security event is logged
- And alert is sent to security channel
- And agent is blocked (if policy = reject)
```

#### US5: Platform Filters Report by Effective Capabilities
```
As the Platform,
I want to only accept findings for capabilities the agent is authorized for
So that agents cannot inject unauthorized data

Acceptance Criteria:
- Given agent with effective_capabilities = [sast]
- When agent submits report with SAST + DAST + SCA findings
- Then ONLY SAST findings are ingested
- And DAST and SCA findings are rejected
- And response includes rejection details
- And security event is logged for unauthorized attempt
```

#### US6: Agent Receives Clear Feedback on Rejected Findings
```
As an Agent,
I want to know which findings were rejected and why
So that I can alert the operator about misconfiguration

Acceptance Criteria:
- Given report submitted with unauthorized findings
- When platform processes the report
- Then response includes:
  - Count of accepted findings
  - Count of rejected findings per capability
  - Clear reason for rejection
- And agent can log warning to operator
```

### Performance Requirements (SLA)

| Metric | Requirement | Rationale |
|--------|-------------|-----------|
| Heartbeat processing time | < 100ms p99 | Agent sends every 30-60s |
| Tool scan duration | < 30s for 10 tools | Parallel scanning |
| Drift detection latency | < 5 minutes | Next heartbeat after change |
| Alert delivery | < 1 minute | Critical for security events |
| Max agents per platform | 10,000 | Enterprise scale |
| Max concurrent heartbeats | 500/s | 10K agents × 30s interval |
| Capability cache hit rate | > 95% | Reduce DB load |

### Error Handling Matrix

| Situation | Detection | Action | Recovery |
|-----------|-----------|--------|----------|
| Agent offline during tool scan | Scan times out | Use cached results | Retry next interval |
| Heartbeat timeout | No response in 5s | Log warning, retry | Exponential backoff |
| Database failure during update | Transaction error | Rollback, queue retry | Circuit breaker |
| Optimistic lock conflict | RowsAffected = 0 | Reload and retry (max 3) | Return error if exhausted |
| Invalid capability name | Not in known list | Ignore, log warning | Filter out unknown |
| Tool binary missing | exec.LookPath fails | Skip tool | Mark as not detected |
| Version parse failure | Regex no match | Use "unknown" | Still report tool |

### Rollback Plan

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ROLLBACK PROCEDURES                             │
└─────────────────────────────────────────────────────────────────────────┘

Phase 1 Rollback (Database Migration):
├── Run: migrate down -1
├── Columns are nullable, no data loss
└── Old code continues to work

Phase 2 Rollback (Heartbeat Changes):
├── Feature flag: CAPABILITY_VERIFICATION_ENABLED=false
├── Heartbeat ignores capability fields
└── Effective = Declared (legacy behavior)

Phase 3 Rollback (Agent SDK):
├── Agent config: tool_detection.enabled=false
├── Heartbeat omits capability report
└── Platform uses declared as effective

Phase 4 Rollback (Job Dispatch):
├── Feature flag: USE_EFFECTIVE_CAPABILITIES=false
├── Dispatch queries use declared_* columns
└── All declared capabilities are trusted

Full Rollback:
├── Set all feature flags to false
├── Run migration rollback
├── Deploy previous agent SDK version
└── Monitor for 24h before removing code
```

---

## Security Enhancements

### Critical Security Fixes

#### Fix 1: Binary Hash Verification

```go
// agent/internal/tools/detector.go

import (
    "crypto/sha256"
    "io"
    "os"
)

type DetectedTool struct {
    Name         string            `json:"name"`
    Version      string            `json:"version"`
    Path         string            `json:"path"`
    BinaryHash   string            `json:"binary_hash"`   // SHA256 of binary
    Capabilities []string          `json:"capabilities"`
    DetectedAt   time.Time         `json:"detected_at"`
}

// calculateBinaryHash computes SHA256 hash of tool binary
func calculateBinaryHash(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }

    return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (d *Detector) checkTool(ctx context.Context, tool ToolDefinition) *DetectedTool {
    path, err := exec.LookPath(tool.Binary)
    if err != nil {
        return nil
    }

    // Calculate binary hash for integrity verification
    hash, err := calculateBinaryHash(path)
    if err != nil {
        d.logger.Warn("failed to hash binary",
            "tool", tool.Name,
            "path", path,
            "error", err,
        )
        hash = "error:" + err.Error()
    }

    // Run version check...
    version := d.getVersion(ctx, tool, path)

    return &DetectedTool{
        Name:         tool.Name,
        Version:      version,
        Path:         path,
        BinaryHash:   hash,
        Capabilities: tool.Capabilities,
        DetectedAt:   time.Now(),
    }
}
```

#### Fix 2: Rate Limiting on Capability Changes

```go
// api/internal/app/platform_agent_service.go

const (
    MaxCapabilityChangesPerHour = 10
    CapabilityChangeCooldown    = 60 * time.Second
)

func (s *PlatformAgentService) processCapabilityReport(
    ctx context.Context,
    agent *agent.Agent,
    input HeartbeatInput,
) (bool, error) {
    // Check if capabilities actually changed
    if !s.capabilitiesChanged(agent, input) {
        // No change, just update timestamp
        agent.ReportedAt = timePtr(time.Now())
        return false, nil
    }

    // Rate limit check
    if agent.LastCapabilityChangeAt != nil {
        elapsed := time.Since(*agent.LastCapabilityChangeAt)
        if elapsed < CapabilityChangeCooldown {
            s.logger.Warn("capability change rate limited",
                "agent_id", agent.ID,
                "elapsed", elapsed,
                "cooldown", CapabilityChangeCooldown,
            )
            // Use cached capabilities, don't update
            return false, nil
        }
    }

    // Hourly limit check
    if s.getCapabilityChangeCountLastHour(ctx, agent.ID) >= MaxCapabilityChangesPerHour {
        s.logger.Warn("capability change hourly limit exceeded",
            "agent_id", agent.ID,
            "limit", MaxCapabilityChangesPerHour,
        )
        s.emitSecurityEvent(ctx, SecurityEvent{
            Type:    SecurityEventRateLimitExceeded,
            AgentID: agent.ID,
        })
        return false, nil
    }

    // Process the update...
    return s.doProcessCapabilityReport(ctx, agent, input)
}

func (s *PlatformAgentService) capabilitiesChanged(agent *agent.Agent, input HeartbeatInput) bool {
    // Compare sorted slices
    return !slicesEqual(agent.ReportedTools, input.ReportedTools) ||
           !slicesEqual(agent.ReportedCapabilities, input.ReportedCapabilities)
}
```

#### Fix 3: Optimistic Locking for Race Condition Prevention

```go
// api/internal/domain/agent/entity.go

type Agent struct {
    // ... existing fields ...

    // Version for optimistic locking
    Version int64 `json:"version"`
}

// api/internal/infra/postgres/agent_repository.go

func (r *AgentRepository) UpdateWithOptimisticLock(
    ctx context.Context,
    agent *agent.Agent,
) error {
    result, err := r.db.ExecContext(ctx, `
        UPDATE agents SET
            reported_capabilities = $1,
            reported_tools = $2,
            reported_tool_versions = $3,
            reported_at = $4,
            effective_capabilities = $5,
            effective_tools = $6,
            capability_drift = $7,
            last_capability_change_at = $8,
            version = version + 1,
            updated_at = NOW()
        WHERE id = $9 AND version = $10
    `,
        pq.Array(agent.ReportedCapabilities),
        pq.Array(agent.ReportedTools),
        agent.ReportedToolVersions,
        agent.ReportedAt,
        pq.Array(agent.EffectiveCapabilities),
        pq.Array(agent.EffectiveTools),
        agent.CapabilityDrift,
        agent.LastCapabilityChangeAt,
        agent.ID,
        agent.Version,
    )
    if err != nil {
        return fmt.Errorf("update agent: %w", err)
    }

    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        return ErrConcurrentUpdate
    }

    agent.Version++
    return nil
}

// With retry logic
func (s *PlatformAgentService) updateAgentWithRetry(
    ctx context.Context,
    agentID shared.ID,
    updateFn func(*agent.Agent) error,
) error {
    const maxRetries = 3

    for attempt := 0; attempt < maxRetries; attempt++ {
        // Load fresh agent
        agent, err := s.repo.GetByID(ctx, agentID)
        if err != nil {
            return err
        }

        // Apply update
        if err := updateFn(agent); err != nil {
            return err
        }

        // Save with optimistic lock
        err = s.repo.UpdateWithOptimisticLock(ctx, agent)
        if err == ErrConcurrentUpdate {
            s.logger.Debug("concurrent update detected, retrying",
                "agent_id", agentID,
                "attempt", attempt+1,
            )
            continue
        }
        return err
    }

    return fmt.Errorf("max retries exceeded for agent update: %s", agentID)
}
```

#### Fix 4: Input Validation for Command Injection Prevention

```go
// agent/internal/tools/detector.go

import (
    "path/filepath"
    "regexp"
)

var (
    // Only allow alphanumeric, dash, underscore, dot
    validBinaryName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

    // Whitelist of allowed tool binaries
    allowedBinaries = map[string]bool{
        "semgrep":  true,
        "trivy":    true,
        "gitleaks": true,
        "nuclei":   true,
        "nmap":     true,
        "nikto":    true,
        "zap.sh":   true,
    }
)

func (d *Detector) validateToolDefinition(tool ToolDefinition) error {
    // Validate binary name
    if !validBinaryName.MatchString(tool.Binary) {
        return fmt.Errorf("invalid binary name: %s", tool.Binary)
    }

    // Check whitelist
    if !allowedBinaries[tool.Binary] {
        return fmt.Errorf("binary not in whitelist: %s", tool.Binary)
    }

    // Validate version command args
    for _, arg := range tool.VersionCmd {
        if strings.ContainsAny(arg, ";|&`$(){}[]<>") {
            return fmt.Errorf("invalid characters in version command: %s", arg)
        }
    }

    return nil
}

func (d *Detector) checkTool(ctx context.Context, tool ToolDefinition) *DetectedTool {
    // Validate first
    if err := d.validateToolDefinition(tool); err != nil {
        d.logger.Error("invalid tool definition", "tool", tool.Name, "error", err)
        return nil
    }

    path, err := exec.LookPath(tool.Binary)
    if err != nil {
        return nil
    }

    // Verify path is in expected locations
    absPath, err := filepath.Abs(path)
    if err != nil {
        return nil
    }
    if !d.isInAllowedPath(absPath) {
        d.logger.Warn("tool found in unexpected location",
            "tool", tool.Name,
            "path", absPath,
        )
        // Still allow but log for monitoring
    }

    // ... rest of detection
}

func (d *Detector) isInAllowedPath(path string) bool {
    allowedPrefixes := []string{
        "/usr/bin/",
        "/usr/local/bin/",
        "/opt/",
        "/home/", // For user-installed tools
    }
    for _, prefix := range allowedPrefixes {
        if strings.HasPrefix(path, prefix) {
            return true
        }
    }
    return false
}
```

#### Fix 5: Capability Report Integrity (Optional Enhancement)

```go
// For high-security environments: sign capability reports

// agent/internal/platform/heartbeat.go

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "strconv"
    "time"
)

type SignedHeartbeatInput struct {
    HeartbeatInput

    // Signature fields
    Timestamp int64  `json:"timestamp"`
    Nonce     string `json:"nonce"`
    Signature string `json:"signature"`
}

func (a *Agent) createSignedHeartbeat() *SignedHeartbeatInput {
    input := a.createHeartbeat()

    timestamp := time.Now().Unix()
    nonce := generateNonce()

    // Create signature: HMAC-SHA256(secret, capabilities|tools|timestamp|nonce)
    signData := strings.Join(input.ReportedCapabilities, ",") + "|" +
                strings.Join(input.ReportedTools, ",") + "|" +
                strconv.FormatInt(timestamp, 10) + "|" +
                nonce

    mac := hmac.New(sha256.New, []byte(a.config.SigningSecret))
    mac.Write([]byte(signData))
    signature := hex.EncodeToString(mac.Sum(nil))

    return &SignedHeartbeatInput{
        HeartbeatInput: *input,
        Timestamp:      timestamp,
        Nonce:          nonce,
        Signature:      signature,
    }
}

// Platform side verification
func (s *PlatformAgentService) verifyHeartbeatSignature(
    agent *agent.Agent,
    input *SignedHeartbeatInput,
) error {
    // Check timestamp freshness (prevent replay)
    if time.Now().Unix()-input.Timestamp > 300 { // 5 minutes
        return ErrHeartbeatExpired
    }

    // Check nonce not reused
    if s.nonceCache.Has(input.Nonce) {
        return ErrNonceReused
    }
    s.nonceCache.Add(input.Nonce, struct{}{}, 10*time.Minute)

    // Verify signature
    signData := strings.Join(input.ReportedCapabilities, ",") + "|" +
                strings.Join(input.ReportedTools, ",") + "|" +
                strconv.FormatInt(input.Timestamp, 10) + "|" +
                input.Nonce

    mac := hmac.New(sha256.New, []byte(agent.SigningSecret))
    mac.Write([]byte(signData))
    expected := hex.EncodeToString(mac.Sum(nil))

    if !hmac.Equal([]byte(expected), []byte(input.Signature)) {
        return ErrInvalidSignature
    }

    return nil
}
```

### Security Checklist

- [ ] Binary hash verification implemented
- [ ] Rate limiting on capability changes
- [ ] Optimistic locking for race conditions
- [ ] Input validation for command injection
- [ ] Capability report signing (optional)
- [ ] Security event logging
- [ ] Audit trail for all changes
- [ ] Execution mode mismatch detection

---

## Database Optimization

### Optimized Schema

```sql
-- Migration: agent_capability_verification_v2

-- Add version for optimistic locking
ALTER TABLE agents ADD COLUMN IF NOT EXISTS version BIGINT DEFAULT 1;

-- Add rate limiting tracking
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_capability_change_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS capability_change_count_hour INT DEFAULT 0;

-- Add generated column for fast drift queries
ALTER TABLE agents ADD COLUMN IF NOT EXISTS has_capability_drift BOOLEAN
GENERATED ALWAYS AS (
    capability_drift IS NOT NULL
    AND (capability_drift->>'has_missing')::boolean = true
) STORED;

-- Optimized compound index for job dispatch
-- This covers the most common query pattern
DROP INDEX IF EXISTS idx_agents_effective_capabilities;
DROP INDEX IF EXISTS idx_agents_effective_tools;

CREATE INDEX idx_agents_dispatch_optimized
ON agents (status, health, load_score)
INCLUDE (id, effective_capabilities, effective_tools, max_concurrent_jobs, current_jobs)
WHERE status = 'active' AND health = 'online';

-- Index for drift monitoring dashboard
CREATE INDEX idx_agents_has_drift
ON agents (has_capability_drift, updated_at DESC)
WHERE has_capability_drift = true;

-- Index for rate limiting checks
CREATE INDEX idx_agents_capability_changes
ON agents (last_capability_change_at)
WHERE last_capability_change_at IS NOT NULL;

-- Partial GIN index for capability search (only for agents with capabilities)
CREATE INDEX idx_agents_effective_caps_gin
ON agents USING GIN (effective_capabilities)
WHERE array_length(effective_capabilities, 1) > 0;

-- Index for execution mode mismatch monitoring
CREATE INDEX idx_agents_mode_mismatch
ON agents (execution_mode_mismatch, updated_at DESC)
WHERE execution_mode_mismatch = true;
```

### Optimized Queries

#### Job Dispatch Query (Before vs After)

```sql
-- BEFORE (unoptimized):
SELECT * FROM agents
WHERE status = 'active'
  AND health = 'online'
  AND 'sca' = ANY(effective_capabilities)
  AND 'trivy' = ANY(effective_tools)
ORDER BY load_score ASC
LIMIT 1;
-- Cost: Seq scan + array contains + sort

-- AFTER (optimized with compound index):
SELECT id, effective_capabilities, effective_tools, load_score
FROM agents
WHERE status = 'active'
  AND health = 'online'
  AND effective_capabilities @> ARRAY['sca']
  AND effective_tools @> ARRAY['trivy']
ORDER BY load_score ASC
LIMIT 1;
-- Cost: Index scan only (covering index)
```

#### Batch Job Dispatch

```sql
-- Instead of N queries for N jobs, use batch query:
WITH job_requirements AS (
    SELECT
        j.id as job_id,
        j.required_capability,
        j.required_tool
    FROM pending_jobs j
    WHERE j.status = 'queued'
    LIMIT 100
),
capable_agents AS (
    SELECT
        a.id as agent_id,
        a.effective_capabilities,
        a.effective_tools,
        a.load_score,
        a.max_concurrent_jobs - a.current_jobs as available_slots
    FROM agents a
    WHERE a.status = 'active'
      AND a.health = 'online'
      AND a.current_jobs < a.max_concurrent_jobs
)
SELECT
    jr.job_id,
    ca.agent_id,
    ca.load_score
FROM job_requirements jr
CROSS JOIN LATERAL (
    SELECT agent_id, load_score
    FROM capable_agents ca
    WHERE ca.effective_capabilities @> ARRAY[jr.required_capability]
      AND (jr.required_tool IS NULL OR ca.effective_tools @> ARRAY[jr.required_tool])
    ORDER BY ca.load_score ASC
    LIMIT 1
) ca;
-- Single query for batch dispatch
```

### Caching Strategy

```go
// api/internal/infra/cache/agent_capability_cache.go

package cache

import (
    "context"
    "time"

    "github.com/hashicorp/golang-lru/v2"
)

type AgentCapabilityCache struct {
    cache *lru.Cache[string, *CachedCapabilities]
    ttl   time.Duration
}

type CachedCapabilities struct {
    EffectiveCapabilities []string
    EffectiveTools        []string
    Version               int64
    CachedAt              time.Time
}

func NewAgentCapabilityCache(size int, ttl time.Duration) (*AgentCapabilityCache, error) {
    cache, err := lru.New[string, *CachedCapabilities](size)
    if err != nil {
        return nil, err
    }
    return &AgentCapabilityCache{
        cache: cache,
        ttl:   ttl,
    }, nil
}

func (c *AgentCapabilityCache) Get(agentID string) (*CachedCapabilities, bool) {
    cached, ok := c.cache.Get(agentID)
    if !ok {
        return nil, false
    }

    // Check TTL
    if time.Since(cached.CachedAt) > c.ttl {
        c.cache.Remove(agentID)
        return nil, false
    }

    return cached, true
}

func (c *AgentCapabilityCache) Set(agentID string, caps *CachedCapabilities) {
    caps.CachedAt = time.Now()
    c.cache.Add(agentID, caps)
}

func (c *AgentCapabilityCache) Invalidate(agentID string) {
    c.cache.Remove(agentID)
}

// Usage in service
func (s *PlatformAgentService) GetEffectiveCapabilities(
    ctx context.Context,
    agentID string,
) ([]string, []string, error) {
    // Try cache first
    if cached, ok := s.capCache.Get(agentID); ok {
        return cached.EffectiveCapabilities, cached.EffectiveTools, nil
    }

    // Load from DB
    agent, err := s.repo.GetByID(ctx, shared.ID(agentID))
    if err != nil {
        return nil, nil, err
    }

    // Cache result
    s.capCache.Set(agentID, &CachedCapabilities{
        EffectiveCapabilities: agent.EffectiveCapabilities,
        EffectiveTools:        agent.EffectiveTools,
        Version:               agent.Version,
    })

    return agent.EffectiveCapabilities, agent.EffectiveTools, nil
}
```

### Query Performance Comparison

| Query | Before | After | Improvement |
|-------|--------|-------|-------------|
| Single agent dispatch | 15ms | 2ms | 87% faster |
| Batch dispatch (100 jobs) | 1500ms | 50ms | 97% faster |
| Drift report | 200ms | 10ms | 95% faster |
| Heartbeat update | 20ms | 8ms | 60% faster |
| Cache hit | N/A | 0.1ms | - |

---

## Revised Implementation Plan

### Timeline Overview

```
Week 1: Foundation
├── Day 1-2: Phase 0 - Prerequisites
├── Day 3-5: Phase 1 - Database & Core
└── Day 5: Phase 1 Testing

Week 2: Core Features
├── Day 1-2: Phase 2 - Heartbeat + Security
├── Day 3-4: Phase 3 - Tool Detector + SDK
└── Day 5: Integration Testing

Week 3: Data Flow Security
├── Day 1-2: Phase 4 - Report Ingestion Filtering ⭐ NEW
├── Day 3-4: Phase 5 - Job Dispatch Optimization
└── Day 5: Integration Testing

Week 4: Advanced Features
├── Day 1-2: Phase 6 - Execution Mode Verification
├── Day 3-4: Phase 7 - Admin UI & Alerts
└── Day 5: Security Testing

Week 5: Polish & Rollout
├── Day 1-2: Phase 8 - Testing & Rollout
├── Day 3: Load Testing
├── Day 4: Gradual Rollout (10% → 50%)
└── Day 5: Full Rollout + Monitoring
```

### Phase 0: Prerequisites (2 days)

**Deliverables:**
- [ ] Feature flags defined in config
- [ ] Acceptance criteria documented
- [ ] SLA metrics defined
- [ ] Rollback procedures documented
- [ ] Monitoring dashboard skeleton

**Feature Flags:**
```yaml
feature_flags:
  capability_verification_enabled: false  # Master switch
  use_effective_capabilities: false       # Job dispatch
  filter_reports_by_capability: false     # Report ingestion filtering ⭐ NEW
  tool_detection_enabled: false           # Agent SDK
  execution_mode_verification: false      # Mode checks
  capability_report_signing: false        # Optional security
```

### Phase 1: Database & Core (3 days)

**Deliverables:**
- [ ] Migration script with optimized indexes
- [ ] Agent entity with new fields
- [ ] CapabilityDrift value object
- [ ] Repository methods with optimistic locking
- [ ] Unit tests (>90% coverage)

**Key Files:**
```
api/internal/infra/postgres/migrations/
  └── 20240130_agent_capability_verification.sql

api/internal/domain/agent/
  ├── entity.go (updated)
  ├── capability_drift.go (new)
  └── errors.go (updated)

api/internal/infra/postgres/
  └── agent_repository.go (updated)
```

### Phase 2: Heartbeat + Security (2 days)

**Deliverables:**
- [ ] HeartbeatInput extended with capabilities
- [ ] HeartbeatResponse with drift info
- [ ] Capability processing logic
- [ ] Rate limiting implementation
- [ ] Optimistic lock retry logic
- [ ] Integration tests

**Key Files:**
```
api/internal/app/
  ├── platform_agent_service.go (updated)
  └── platform_agent_service_test.go (updated)

api/internal/infra/cache/
  └── agent_capability_cache.go (new)
```

### Phase 3: Tool Detector + SDK (2 days)

**Deliverables:**
- [ ] ToolDetector with hash verification
- [ ] KnownTools registry
- [ ] Hot reload mechanism
- [ ] Agent heartbeat integration
- [ ] SDK unit tests

**Key Files:**
```
sdk/pkg/agent/internal/tools/
  ├── detector.go (new)
  ├── detector_test.go (new)
  └── known_tools.go (new)

sdk/pkg/agent/internal/platform/
  └── heartbeat.go (updated)
```

### Phase 4: Report Ingestion Filtering (2 days)

**Deliverables:**
- [ ] CapabilityFilter for report ingestion
- [ ] Finding-to-capability mapping
- [ ] Ingest service integration
- [ ] Output extension with rejection details
- [ ] Unit tests for filtering logic

**Key Files:**
```
api/internal/app/ingest/
  ├── capability_filter.go (new)
  ├── capability_filter_test.go (new)
  ├── service.go (updated - integrate filter)
  └── types.go (updated - add rejection fields)
```

### Phase 5: Job Dispatch Optimization (2 days)

**Deliverables:**
- [ ] Batch dispatch query
- [ ] Dispatch algorithm using effective caps
- [ ] Performance benchmarks
- [ ] Load tests

**Key Files:**
```
api/internal/app/
  └── job_dispatcher.go (updated)

api/internal/infra/postgres/
  └── agent_repository.go (dispatch queries)
```

### Phase 6: Execution Mode Verification (2 days)

**Deliverables:**
- [ ] Mode mismatch detection
- [ ] Policy enforcement (warn/reject)
- [ ] Security event emission
- [ ] Behavioral heuristics (optional)

**Key Files:**
```
api/internal/app/
  └── platform_agent_service.go (mode verification)

api/internal/domain/agent/
  └── execution_mode.go (new)
```

### Phase 7: Admin UI & Alerts (2 days)

**Deliverables:**
- [ ] Drift indicators in agent list
- [ ] Drift acknowledgment endpoint
- [ ] Alert webhook integration
- [ ] Dashboard widgets

**Key Files:**
```
api/internal/interfaces/http/
  └── agent_handler.go (drift endpoints)

api/internal/app/
  └── alert_service.go (new)
```

### Phase 8: Testing & Rollout (3 days)

**Deliverables:**
- [ ] Load test: 1000 agents, 500 heartbeats/s
- [ ] Security penetration test
- [ ] Gradual rollout execution
- [ ] Production monitoring

**Rollout Schedule:**
```
Day 1: 10% of agents (feature flag)
Day 2: 50% of agents (monitor for issues)
Day 3: 100% of agents (full rollout)
Day 4+: Monitor and optimize
```

### Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Heartbeat p99 latency | < 100ms | Prometheus |
| Drift detection time | < 5 min | Alert timing |
| False positive drift | < 1% | Manual review |
| Job dispatch accuracy | 100% | No failed jobs due to missing tools |
| **Report filtering accuracy** | **100%** | **No unauthorized findings ingested** |
| **Filtering latency overhead** | **< 10ms** | **Added to ingest p99** |
| Cache hit rate | > 95% | Cache metrics |
| Rollback time | < 5 min | Runbook test |

---

## Appendix: Configuration Reference

### Platform Configuration

```yaml
# api/config/agent_capability.yaml

agent_capability:
  # Feature flags
  enabled: true
  use_effective_capabilities: true

  # Verification settings
  verification_timeout: 10m           # Time to wait for first report
  verification_grace_period: 2m       # Grace period before "pending" status

  # Rate limiting
  max_capability_changes_per_hour: 10
  capability_change_cooldown: 60s

  # Caching
  cache_size: 10000                   # Max agents in cache
  cache_ttl: 5m                       # Cache entry TTL

  # Alerting
  drift_alerting_enabled: true
  alert_cooldown: 1h                  # Don't spam alerts
  alert_channels:
    - webhook
    - email

  # Execution mode verification
  execution_mode_verification: true
  mismatch_policy: reject             # warn, reject, adapt

  # Known capabilities (for validation)
  known_capabilities:
    - sast
    - sca
    - secrets
    - iac
    - dast
    - container
    - infra
    - api
    - recon
    - web3
    - collector

  # Tool to capability mapping
  tool_capabilities:
    semgrep: [sast]
    trivy: [sca, container, iac]
    gitleaks: [secrets]
    trufflehog: [secrets]
    nuclei: [dast, infra]
    nmap: [infra, recon]
    nikto: [dast]
    zap: [dast, api]
```

### Agent Configuration

```yaml
# agent/config/tools.yaml

tool_detection:
  enabled: true
  scan_interval: 5m                   # How often to scan
  check_timeout: 5s                   # Per-tool timeout
  notify_on_change: true              # Immediate heartbeat on change

  # Additional search paths
  extra_paths:
    - /opt/security-tools/bin
    - /usr/local/bin
    - $HOME/.local/bin

  # Hash verification
  verify_hashes: true

  # Custom tools (beyond built-in)
  custom_tools:
    - name: custom-scanner
      binary: custom-scanner
      version_cmd: ["--version"]
      version_regex: "v(\\d+\\.\\d+\\.\\d+)"
      capabilities: ["custom"]

heartbeat:
  interval: 30s
  include_capabilities: true
  sign_reports: false                 # Enable for high-security
```

---

*Document last updated: 2024-01-30*
*Review status: Comprehensive review completed*
*Next review: After Phase 1 implementation*
