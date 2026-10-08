# Scan Orchestration Architecture

> **Last Updated**: January 20, 2026
> **Status**: Production Ready
>
> **Being replaced.** The target model (Scan → Run → Task, `partial` runs,
> rrule schedules, engines, Automations) and the current state are in
> [scan-lifecycle.md](scan-lifecycle.md) and
> [RFC-046](../rfcs/RFC-046-scans-redesign.md). Parts of this page predate
> zones, leases and the P0 fixes; prefer those documents where they differ.

## Overview

OpenCTEM's scan orchestration system manages the complete lifecycle of security scans, from scheduling through execution to results collection. The system uses a distributed agent architecture with pipeline-based workflow orchestration.

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
│  │ (pipeline_      │     Creates Command with scan_run_step_id, payload          │
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
// FindAvailableWithTool finds the least-loaded ONLINE agent that has the tool
// AND has spare job capacity (internal/infra/postgres/agent_repository.go).
func (r *AgentRepository) FindAvailableWithTool(ctx, tenantID, tool string) (*Agent, error) {
    query := `
        SELECT * FROM agents
        WHERE tenant_id = $1
          AND status = 'active'
          AND health = 'online'                    -- must have heartbeat recently
          AND last_seen_at IS NOT NULL             -- never selects a never-seen agent
          AND $2 = ANY(tools)
          AND current_jobs < max_concurrent_jobs   -- must have spare capacity
        ORDER BY current_jobs ASC, total_scans ASC -- least-loaded first
        LIMIT 1
    `
    return r.db.QueryRow(ctx, query, tenantID, tool)
}
```

> **The dispatch predicate changed (undead-agent fix).** The old query matched
> `health IN ('online','unknown')` and ordered by `total_scans` only. That let an
> **undead** agent (one that registered but never sent a heartbeat, `health =
> 'unknown'`, or one already at capacity) win dispatch, so commands were handed to
> an agent that never picked them up. The current predicate requires
> `health = 'online' AND last_seen_at IS NOT NULL AND current_jobs <
> max_concurrent_jobs` and load-balances by `current_jobs ASC, total_scans ASC`.

### Step commands name their scanner

A pipeline or workflow step becomes a `scan` command whose payload names the
step's tool twice: `scanner` (what the sensor SDK runs, `ScanCommandPayload`)
and `preferred_tool` (read by the platform's tool gate, which offers the
command only to a sensor whose effective tools include it). Direct run targets
are copied to the top-level `targets`. Before api RFC-036 P0 only
`preferred_tool` was sent, and every step failed on the sensor with
`scanner not found: `. `required_capabilities` is the step's capability list;
the queue-time step check requires it to be a subset of the tool's catalog
capabilities, and the poll offers the command only to a sensor that
advertises all of them.

The recon tools (subfinder, dnsx, naabu, httpx, katana) ship in the sensor's
full and platform images and take a target list, so a run of one of them is
one command with every target, like nuclei.

**System presets** (migration 000061, fixed by 000270): every step of an
active preset names a shipped tool with catalog capabilities
(`TestPresetPipelines_UseShippedTools`). "Web Vulnerability Scan" and "API
Security Testing" are inactive: their tools (dalfox, sqlmap, kiterunner,
ffuf) are not shipped and they are intrusive, which RFC-036 O3 keeps opt-in.
Steps still do not pass outputs to the next step (RFC-036 E6, P3).

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

### 6. Editing a pipeline keeps its run history

A pipeline's steps are edited in place. Every write (the builder's full save,
`PUT /api/v1/scan-workflows/{id}` with `steps`, and the single-step add, update and
delete endpoints) goes through one repository call, `StepRepository.MutateSteps`
(`internal/infra/postgres/pipeline_step_mutate.go`), in one transaction:

1. **Lock the pipeline** (`FOR UPDATE`, tenant-scoped; another tenant's
   pipeline is not found). A run insert takes a `KEY SHARE` lock on the same
   row through its foreign key, so a save and a run start never interleave.
2. **Refuse while a run of the pipeline is pending or running**
   (`409 PIPELINE_RUN_ACTIVE`). A running run reads the step definitions as it
   advances, so a mid-run edit would change what the rest of that run does.
3. **Match the saved steps to the current ones**: by the step `id` the client
   sends, then by `step_key`. Only ids of the pipeline's own steps are
   honored; a client-side temporary id or another pipeline's step id makes
   the entry a new step with a server-generated id.
4. **Update matched steps in place** (they keep their id, so their step runs
   and chaining inputs in `scan_step_outputs` stay attached), insert new ones,
   delete the rest.

Deleting a step never deletes history: `scan_run_steps.step_id` is
`ON DELETE SET NULL` (migration 001159), and each step run carries the step's
`step_key`, `step_name` and `tool` as they were when it was created. The run
detail shows a removed step's runs by that snapshot.

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
    pipeline_template_id UUID REFERENCES scan_workflows(id),
    schedule_type VARCHAR(20),  -- manual, daily, weekly, cron
    cron_expression VARCHAR(100),
    next_run_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

-- Pipeline Runs
CREATE TABLE scan_runs (
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
CREATE TABLE scan_run_steps (
    id UUID PRIMARY KEY,
    scan_run_id UUID REFERENCES scan_runs(id),
    step_id UUID REFERENCES scan_workflow_steps(id) ON DELETE SET NULL,  -- NULL once the step is removed
    step_key VARCHAR(100) NOT NULL,
    step_name VARCHAR(255),  -- copied from the step when the step run is created
    tool VARCHAR(100),       -- copied from the step when the step run is created
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
    scan_run_id UUID REFERENCES scan_runs(id),
    scan_run_step_id UUID REFERENCES scan_run_steps(id),
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
-- Agent-tool matching (for FindAvailableWithTool). Supports the current
-- dispatch predicate: online-only, has-heartbeat, capacity-gated, load-ordered.
CREATE INDEX idx_agents_tenant_active_online
ON agents(tenant_id, current_jobs ASC, total_scans ASC)
WHERE status = 'active' AND health = 'online' AND last_seen_at IS NOT NULL;

-- Scan scheduler (for ListDueForExecution)
CREATE INDEX idx_scans_due_for_execution
ON scans(next_run_at)
WHERE status = 'active' AND schedule_type != 'manual' AND next_run_at IS NOT NULL;

-- Command lookup by step
CREATE INDEX idx_commands_scan_run_step_id
ON commands(scan_run_step_id) WHERE scan_run_step_id IS NOT NULL;
```

## Prometheus Metrics

No metric carries a tenant, sensor, pipeline, run or user id as a label
(RFC-046 B9, enforced by `internal/metrics/labels_test.go`); per-tenant views
come from logs (`tenant_id`, `run_id`) and traces.

| Metric | Labels | What |
|---|---|---|
| `scan_runs_total` | `status` | runs started and settled |
| `scan_runs_in_progress` | — | runs in progress (this replica) |
| `scan_run_steps_total` | `step_key`, `status` | step outcomes |
| `commands_total`, `commands_expired_total` | `type`, `status` / — | command outcomes, expiries |
| `command_claims_total` | `mode` (`claim`, `claim_n`) | commands sensors claimed |
| `command_leases_expired_total` | — | commands re-queued after their lease ran out |
| `scan_runs_reaped_total` | `reason` (`deadline`, `unclaimed`) | runs the timeout controller ended |
| `scans_scheduled_total`, `scan_schedule_outcomes_total` | — / `outcome` | scheduler occurrences and what they became |

## Error Handling & Retries

### Retry Configuration

```go
// In scan_workflow_steps table
max_retries INT DEFAULT 3

// In scan_run_steps table
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
GET    /api/v1/scan-runs            # List runs
GET    /api/v1/scan-runs/{id}       # Get run details
GET    /api/v1/scan-runs/{id}/steps # Get step runs
```

### Sensor API (protocol v2)

```
POST   /api/v2/sensor/heartbeat                  # Heartbeat and doorbell
GET    /api/v2/sensor/commands                   # Poll for commands
POST   /api/v2/sensor/commands/{id}/claim        # Claim a command
POST   /api/v2/sensor/commands/{id}/start        # Start execution
POST   /api/v2/sensor/commands/{id}/complete     # Complete with results
POST   /api/v2/sensor/commands/{id}/fail         # Report failure
```

Protocol v1 (`/api/v1/agent/*`) was retired on 2026-10-05; see
[sensors.md](sensors.md#protocol-v2-control-plane). Tenant and module checks
come from the sensor key; the heartbeat is never module-gated, so the fleet
stays visible whatever the tenant's modules.

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

# 3. Sensor polls for command
GET /api/v2/sensor/commands
# Returns command with step_key, preferred_tool, payload
# (targets re-checked against the current scope first; see
# active-probe-gate.md "Re-check at claim")

# 4. Sensor executes and reports
POST /api/v2/sensor/commands/{id}/claim
POST /api/v2/sensor/commands/{id}/start
POST /api/v2/sensor/commands/{id}/complete
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
