# Scan Orchestration Architecture

> **Last Updated**: January 20, 2026
> **Status**: Production Ready

## Overview

Exploop's scan orchestration system manages the complete lifecycle of security scans, from scheduling through execution to results collection. The system uses a distributed agent architecture with pipeline-based workflow orchestration.

## System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SCAN ORCHESTRATION FLOW                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. SCHEDULING                                                               │
│  ┌─────────────────┐                                                        │
│  │ Scan Scheduler  │ ──► Checks due scans every 1 minute                    │
│  │ (scan_scheduler │     Triggers TriggerScan() for each due scan           │
│  │  .go)           │     Updates next_run_at to prevent re-trigger          │
│  └────────┬────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  2. PIPELINE CREATION                                                        │
│  ┌─────────────────┐                                                        │
│  │ Scan Service    │ ──► Creates PipelineRun with status=running            │
│  │ (scan_service   │     Creates StepRuns based on pipeline template        │
│  │  .go)           │     Queues first steps (no dependencies)               │
│  └────────┬────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  3. STEP EXECUTION                                                           │
│  ┌─────────────────┐                                                        │
│  │ Pipeline Service│ ──► QueueStep() finds agent with matching tool         │
│  │ (pipeline_      │     Creates Command with step_run_id, payload          │
│  │  service.go)    │     Agent polls and executes command                   │
│  └────────┬────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  4. COMMAND LIFECYCLE                                                        │
│  ┌─────────────────┐                                                        │
│  │     Agent       │ ──► Poll → ACK → Start → Complete/Fail                 │
│  │                 │     Reports results back via Agent API                 │
│  └────────┬────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  5. PROGRESSION                                                              │
│  ┌─────────────────┐                                                        │
│  │ Command Handler │ ──► OnStepCompleted() triggers next dependent steps    │
│  │ (command_       │     Checks if all steps done → completes pipeline      │
│  │  handler.go)    │     Handles retries on failure                         │
│  └─────────────────┘                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Scan Scheduling

```go
// ScanScheduler runs every CheckInterval (default: 1 minute)
type ScanScheduler struct {
    scanRepo    scan.Repository
    scanService *ScanService
    interval    time.Duration   // 1 minute default
    batchSize   int             // 50 scans per cycle
}

// Flow:
// 1. ListDueForExecution(now) - finds scans where next_run_at <= NOW()
// 2. UpdateNextRunAt() - immediately prevents re-trigger
// 3. TriggerScan() - creates pipeline run
```

### 2. Pipeline Run Creation

```go
// TriggerScan creates a new pipeline execution
func (s *ScanService) TriggerScan(ctx, input) (*TriggerScanExecOutput, error) {
    // 1. Load scan configuration
    scan := s.scanRepo.GetByID(input.ScanID)

    // 2. Load pipeline template with steps
    template := s.pipelineRepo.GetTemplateByID(scan.PipelineTemplateID)

    // 3. Create pipeline run
    pipelineRun := s.pipelineRepo.CreateRun(template, scan)

    // 4. Create step runs from template steps
    for _, step := range template.Steps {
        stepRun := CreateStepRun(pipelineRun, step)
    }

    // 5. Queue first steps (those with no dependencies)
    s.pipelineService.QueueFirstSteps(pipelineRun)
}
```

### 3. Agent-Tool Matching

```go
// FindAvailableWithTool finds agent with specific tool capability
func (r *AgentRepository) FindAvailableWithTool(ctx, tenantID, tool string) (*Agent, error) {
    query := `
        SELECT * FROM agents
        WHERE tenant_id = $1
          AND status = 'active'
          AND health IN ('online', 'unknown')
          AND $2 = ANY(tools)
        ORDER BY total_scans ASC  -- Least loaded agent first
        LIMIT 1
    `
    return r.db.QueryRow(ctx, query, tenantID, tool)
}
```

### 4. Command Execution

```
Command Lifecycle:
┌─────────┐    ┌──────────────┐    ┌─────────┐    ┌───────────┐
│ pending │───►│ acknowledged │───►│ running │───►│ completed │
└─────────┘    └──────────────┘    └─────────┘    └───────────┘
                                        │              │
                                        │              ▼
                                        │         OnStepCompleted()
                                        │              │
                                        ▼              ▼
                                   ┌────────┐    Queue dependent
                                   │ failed │    steps
                                   └────────┘
                                        │
                                        ▼
                                   CanRetry() ?
                                   PrepareRetry()
```

### 5. Pipeline Progression

```go
// OnStepCompleted is called when a command completes successfully
func (s *PipelineService) OnStepCompleted(ctx, pipelineRunID, stepKey string, findingsCount int, output map[string]any) error {
    // 1. Mark step run as completed
    s.stepRunRepo.UpdateStatus(stepRun.ID, "completed")

    // 2. Find dependent steps that are now ready
    dependentSteps := s.findReadyDependentSteps(pipelineRunID, stepKey)

    // 3. Queue each ready step
    for _, step := range dependentSteps {
        s.QueueStep(ctx, pipelineRun, step, prevOutput)
    }

    // 4. Check if pipeline is complete
    if s.allStepsCompleted(pipelineRunID) {
        s.pipelineRunRepo.UpdateStatus(pipelineRunID, "completed")
    }
}
```

## Key Components

### Scan Scheduler (`api/internal/app/scan_scheduler.go`)

- Runs as a background goroutine
- Checks for due scans every minute
- Uses `sync.Map` to track running scans (prevent double-trigger)
- Graceful shutdown via `Stop()` method

### Command Expiration Checker (`api/internal/app/command_expiration_checker.go`)

- Handles commands that exceed their timeout
- Marks expired commands as failed
- Triggers `OnStepFailed()` for pipeline progression
- Enables automatic retries if configured

### Pipeline Service (`api/internal/app/pipeline_service.go`)

- Orchestrates pipeline execution
- Manages step dependencies
- Routes commands to capable agents
- Handles retries and failure scenarios

### Command Handler (`api/internal/infra/http/handler/command_handler.go`)

- Receives agent status updates
- Triggers pipeline progression asynchronously
- Uses `context.Background()` for async operations (critical fix)

## Database Schema

### Key Tables

```sql
-- Scans (scan configurations)
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    pipeline_template_id UUID REFERENCES pipeline_templates(id),
    schedule_type VARCHAR(20),  -- manual, daily, weekly, cron
    cron_expression VARCHAR(100),
    next_run_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

-- Pipeline Runs
CREATE TABLE pipeline_runs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    pipeline_template_id UUID NOT NULL,
    scan_id UUID REFERENCES scans(id),
    status VARCHAR(20) DEFAULT 'pending',  -- pending, running, completed, failed
    total_steps INT,
    completed_steps INT DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Step Runs
CREATE TABLE step_runs (
    id UUID PRIMARY KEY,
    pipeline_run_id UUID REFERENCES pipeline_runs(id),
    step_key VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',  -- pending, queued, running, completed, failed
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    findings_count INT DEFAULT 0,
    error_message TEXT
);

-- Commands
CREATE TABLE commands (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    agent_id UUID REFERENCES agents(id),
    pipeline_run_id UUID REFERENCES pipeline_runs(id),
    step_run_id UUID REFERENCES step_runs(id),
    source_type VARCHAR(20),  -- scan, pipeline
    action VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    payload JSONB,
    result JSONB,
    expires_at TIMESTAMP,
    acknowledged_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);
```

### Critical Indexes

```sql
-- Agent-tool matching (for FindAvailableWithTool)
CREATE INDEX idx_agents_tenant_active_healthy
ON agents(tenant_id, total_scans ASC)
WHERE status = 'active' AND health IN ('online', 'unknown');

-- Scan scheduler (for ListDueForExecution)
CREATE INDEX idx_scans_due_for_execution
ON scans(next_run_at)
WHERE status = 'active' AND schedule_type != 'manual' AND next_run_at IS NOT NULL;

-- Command lookup by step
CREATE INDEX idx_commands_step_run_id
ON commands(step_run_id) WHERE step_run_id IS NOT NULL;
```

## Prometheus Metrics

```go
// Pipeline metrics
var (
    PipelineRunsTotal = prometheus.NewCounterVec(...)     // pipeline_runs_total
    PipelineRunsInProgress = prometheus.NewGaugeVec(...)  // pipeline_runs_in_progress
    StepRunsTotal = prometheus.NewCounterVec(...)         // step_runs_total
)

// Command metrics
var (
    CommandsTotal = prometheus.NewCounterVec(...)         // commands_total
    CommandsExpired = prometheus.NewCounterVec(...)       // commands_expired_total
    CommandDuration = prometheus.NewHistogramVec(...)     // command_duration_seconds
)

// Scheduler metrics
var (
    ScansScheduled = prometheus.NewCounterVec(...)        // scans_scheduled_total
)
```

## Error Handling & Retries

### Retry Configuration

```go
// In pipeline_steps table
max_retries INT DEFAULT 3

// In step_runs table
retry_count INT DEFAULT 0
```

### Retry Flow

```go
func (s *PipelineService) OnStepFailed(ctx, pipelineRunID, stepKey string, errorMsg string) error {
    stepRun := s.getStepRun(pipelineRunID, stepKey)
    step := s.getStep(stepRun.StepID)

    if stepRun.RetryCount < step.MaxRetries {
        // Retry the step
        stepRun.RetryCount++
        stepRun.Status = "queued"
        s.QueueStep(ctx, pipelineRun, step, nil)
    } else {
        // Mark as failed, potentially fail pipeline
        stepRun.Status = "failed"
        s.checkPipelineFailure(pipelineRunID)
    }
}
```

## Multi-Tenant Isolation

Each tenant's scans and agents are completely isolated:

```
Tenant A                          Tenant B
┌──────────────────────┐         ┌──────────────────────┐
│ Scans: scan-a1, a2   │         │ Scans: scan-b1       │
│ Agents: agent-a1     │         │ Agents: agent-b1     │
│ Commands: cmd-a1..   │         │ Commands: cmd-b1..   │
│                      │         │                      │
│ Isolated execution   │         │ Isolated execution   │
└──────────────────────┘         └──────────────────────┘
```

- Agents only see commands from their tenant
- No cross-tenant resource contention
- Natural load isolation without complex scheduling

## Configuration

```yaml
# Scan Scheduler
scan_scheduler:
  check_interval: 1m      # How often to check for due scans
  batch_size: 50          # Max scans to process per cycle

# Command Expiration
command_expiration:
  check_interval: 1m      # How often to check for expired commands
  default_timeout: 30m    # Default command timeout

# Pipeline
pipeline:
  default_step_timeout: 5m
  max_retries: 3
```

## API Endpoints

### Scan Management

```
POST   /api/v1/scans                    # Create scan
GET    /api/v1/scans                    # List scans
GET    /api/v1/scans/{id}               # Get scan
PUT    /api/v1/scans/{id}               # Update scan
DELETE /api/v1/scans/{id}               # Delete scan
POST   /api/v1/scans/{id}/trigger       # Manually trigger scan
```

### Pipeline Management

```
GET    /api/v1/pipeline-templates       # List templates
GET    /api/v1/pipeline-runs            # List runs
GET    /api/v1/pipeline-runs/{id}       # Get run details
GET    /api/v1/pipeline-runs/{id}/steps # Get step runs
```

### Agent API

```
POST   /api/v1/agent/heartbeat          # Agent heartbeat
GET    /api/v1/agent/commands           # Poll for commands
POST   /api/v1/agent/commands/{id}/ack  # Acknowledge command
POST   /api/v1/agent/commands/{id}/start     # Start execution
POST   /api/v1/agent/commands/{id}/complete  # Complete with results
POST   /api/v1/agent/commands/{id}/fail      # Report failure
```

#### Module Gating for Agent Routes

Agent ingest routes are gated by the tenant's subscription plan modules:

| Endpoint | Module Required | Notes |
|----------|-----------------|-------|
| `POST /heartbeat` | None | Always allowed for agent health monitoring |
| `POST /ingest` | `scans` | Finding/asset ingestion |
| `POST /ingest/check` | `scans` | Fingerprint deduplication |
| `POST /ingest/sarif` | `scans` | SARIF format ingestion |
| `GET /commands` | `scans` | Command polling |
| `POST /commands/{id}/*` | `scans` | Command status updates |
| `POST /scans` | `scans` | Scan session registration |
| `PATCH /scans/{id}` | `scans` | Scan session update |
| `GET /scans/{id}` | `scans` | Get scan session |
| `POST /credentials/ingest` | `credentials` | Credential leak ingestion |

> **Note:** The heartbeat endpoint is exempt from module gating to allow agents to report health status even if the tenant's subscription lapses. This ensures visibility into agent fleet status regardless of licensing state.

## Testing

### Test API Keys (Development Only)

```sql
-- Agent 2: test_agent2_key_12345
-- SHA256: 5e9f46e73d6a7e0028f0317227b773a3cb4de767bad4a3ed1bf71a866f074319

-- Agent 3: test_agent3_key_12345
-- SHA256: 3f691ee09b992a87da44b2feffc0038a1f0d92df7a6336bc26a0cb2122db066e
```

### Testing Flow

```bash
# 1. Create a scan with schedule
POST /api/v1/scans
{
  "name": "Daily Security Scan",
  "pipeline_template_id": "...",
  "schedule_type": "daily",
  "next_run_at": "2026-01-20T00:00:00Z"
}

# 2. Wait for scheduler to trigger (or trigger manually)
POST /api/v1/scans/{id}/trigger

# 3. Agent polls for command
GET /api/v1/agent/commands
# Returns command with step_key, preferred_tool, payload

# 4. Agent executes and reports
POST /api/v1/agent/commands/{id}/ack
POST /api/v1/agent/commands/{id}/start
POST /api/v1/agent/commands/{id}/complete
{
  "findings_count": 15,
  "output": { "results": [...] }
}

# 5. Pipeline automatically progresses to next step
```

## Related Documents

- [Architecture Overview](overview.md)
- [Clean Architecture](clean-arch.md)
- [API Endpoints](../api/endpoints.md)
