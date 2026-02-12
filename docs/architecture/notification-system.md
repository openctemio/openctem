# Notification System Architecture

## Overview

OpenCTEM's notification system provides real-time alerts when security findings are detected. It supports multiple providers (Slack, Teams, Telegram, Email, Webhook) with severity filtering, event routing, and full audit history.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Providers | Slack, Microsoft Teams, Telegram, Email (SMTP), Generic Webhook |
| Encryption | AES-256-GCM for credentials |
| Async Pattern | **Transactional Outbox** (PostgreSQL) + Polling scheduler |
| Rate Limiting | In-memory with sync.RWMutex |
| Archive | `notification_events` table with JSONB send results |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          NOTIFICATION SYSTEM FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────┘

TRIGGER SOURCES              TRANSACTIONAL OUTBOX           ARCHIVE
───────────────              ────────────────────           ───────

┌──────────────────┐
│ VulnerabilityService │     ┌─────────────────────────┐
│ CreateFinding()      │     │  notification_outbox    │
│   └─ EnqueueInTx()   │────▶│  (transient queue)      │
└──────────────────────┘     │  - status: pending      │
                             │  - status: processing   │
┌──────────────────┐         │  - status: failed       │
│ ExposureService  │         │  - deleted on success   │
│ CreateExposure() │────────▶│                         │
└──────────────────┘         └───────────┬─────────────┘
                                         │
┌──────────────────┐                     │ Scheduler (5s polling)
│ Future Triggers  │                     │
│ - SLA breaches   │                     ▼
│ - Alert rules    │         ┌─────────────────────────┐
└──────────────────┘         │  NotificationService    │
                             │  processOutboxEntry()   │
                             │    ├─ Match integrations│
                             │    ├─ Send to providers │────▶ Slack/Teams/etc
                             │    ├─ Collect results   │
                             │    └─ Archive & delete  │
                             └───────────┬─────────────┘
                                         │
                                         ▼
                             ┌─────────────────────────┐
                             │  notification_events    │
                             │  (permanent archive)    │
                             │  - status: completed    │
                             │  - status: failed       │
                             │  - status: skipped      │
                             │  - send_results JSONB   │
                             │  - retention: 90 days   │
                             └─────────────────────────┘
```

## Data Flow

### 1. Transactional Outbox (Queue)

The `notification_outbox` table acts as a **transient queue**:

```sql
CREATE TABLE notification_outbox (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,      -- 'new_finding', 'scan_completed'
    aggregate_type VARCHAR(100) NOT NULL,  -- 'finding', 'scan'
    aggregate_id UUID,
    title VARCHAR(500) NOT NULL,
    body TEXT,
    severity VARCHAR(20) NOT NULL,
    url VARCHAR(2000),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_by VARCHAR(100),
    locked_at TIMESTAMPTZ,
    retry_count INT NOT NULL DEFAULT 0,
    last_error TEXT,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Status Lifecycle:**
```
pending → processing → [DELETED after archive]
                    ↳ failed (retries with exponential backoff)
                           ↳ dead (manual intervention required)
```

### 2. Notification Events (Archive)

The `notification_events` table stores **permanent audit trail**:

```sql
CREATE TABLE notification_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    aggregate_type VARCHAR(100) NOT NULL,
    aggregate_id UUID,
    title VARCHAR(500) NOT NULL,
    body TEXT,
    severity VARCHAR(20) NOT NULL,
    url VARCHAR(2000),
    metadata JSONB DEFAULT '{}',

    -- Processing results
    status VARCHAR(20) NOT NULL,           -- 'completed', 'failed', 'skipped'
    integrations_total INT NOT NULL,
    integrations_matched INT NOT NULL,
    integrations_succeeded INT NOT NULL,
    integrations_failed INT NOT NULL,
    send_results JSONB DEFAULT '[]',       -- Per-integration results
    last_error TEXT,
    retry_count INT NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL,       -- When original event was created
    processed_at TIMESTAMPTZ NOT NULL      -- When processing completed
);
```

**Event Status:**
- `completed`: At least one integration succeeded
- `failed`: All integrations failed after retries
- `skipped`: No integrations matched filters

**Send Results JSONB Format:**
```json
[
  {
    "integration_id": "uuid",
    "name": "Slack Alerts",
    "provider": "slack",
    "status": "success",
    "message_id": "1234567890.123456",
    "sent_at": "2024-01-15T10:30:00Z"
  },
  {
    "integration_id": "uuid",
    "name": "Teams Security",
    "provider": "teams",
    "status": "failed",
    "error": "webhook returned 403",
    "sent_at": "2024-01-15T10:30:01Z"
  }
]
```

## Processing Flow

### Step 1: Enqueue in Transaction

```go
// internal/app/vulnerability_service.go

tx, err := s.db.BeginTx(ctx, nil)
defer tx.Rollback()

// 1. Create finding in transaction
if err := s.findingRepo.CreateInTx(ctx, tx, f); err != nil {
    return err
}

// 2. Enqueue notification in the SAME transaction
err = s.notificationService.EnqueueNotificationInTx(ctx, tx, EnqueueNotificationParams{
    TenantID:      f.TenantID(),
    EventType:     "new_finding",
    AggregateType: "finding",
    AggregateID:   &findingUUID,
    Title:         fmt.Sprintf("New %s Finding: %s", f.Severity(), toolName),
    Body:          f.Message(),
    Severity:      f.Severity().String(),
    URL:           fmt.Sprintf("/findings/%s", f.ID()),
})

// 3. Commit transaction - both finding and notification are atomic
return tx.Commit()
```

### Step 2: Scheduler Processing

The scheduler polls every 5 seconds:

```go
// internal/app/notification_scheduler.go

func (s *NotificationScheduler) processBatch() {
    // 1. Fetch and lock pending entries (FOR UPDATE SKIP LOCKED)
    entries, _ := s.service.ProcessOutboxBatch(ctx, workerID, batchSize)

    // Each entry is processed individually
}
```

### Step 3: Process Each Entry

```go
// internal/app/notification_service.go

func (s *NotificationService) processOutboxEntry(ctx context.Context, entry *Outbox) error {
    // 1. Get all integrations for tenant
    integrations, _ := s.getNotificationIntegrationsForTenant(ctx, entry.TenantID())

    // 2. Collect processing results
    results := ProcessingResults{
        IntegrationsTotal:   len(integrations),
        SendResults:         make([]SendResult, 0),
    }

    // 3. Send to each matching integration
    for _, intg := range integrations {
        if !s.shouldSendToIntegration(intg, entry) {
            continue
        }
        results.IntegrationsMatched++

        sendResult := s.sendToIntegration(ctx, intg, entry)
        results.SendResults = append(results.SendResults, sendResult)

        if sendResult.Status == "success" {
            results.IntegrationsSucceeded++
        } else {
            results.IntegrationsFailed++
        }
    }

    // 4. Archive to notification_events
    event := notification.NewEventFromOutbox(entry, results)
    s.eventRepo.Create(ctx, event)

    // 5. Delete from outbox (it's now archived)
    s.outboxRepo.Delete(ctx, entry.ID())

    return nil
}
```

## Retention & Cleanup

The scheduler runs cleanup daily:

| Table | Retention | Notes |
|-------|-----------|-------|
| `notification_outbox` | 7 days (completed), 30 days (failed) | Most entries deleted immediately after archive |
| `notification_events` | 90 days (configurable) | Permanent audit trail |

```go
// internal/app/notification_scheduler.go

type NotificationSchedulerConfig struct {
    ProcessInterval        time.Duration  // 5 seconds
    CleanupInterval        time.Duration  // 24 hours
    BatchSize              int            // 50
    CompletedRetentionDays int            // 7 (for failed archives)
    FailedRetentionDays    int            // 30
    EventRetentionDays     int            // 90 (set to 0 for unlimited)
    StaleMinutes           int            // 10 (for unlocking)
}
```

## API Endpoints

### Tenant-Scoped Outbox API

> **Note**: These endpoints are tenant-scoped. Tenants can only view/manage their own notifications.

```
GET  /api/v1/notification-outbox          # List pending/failed entries
GET  /api/v1/notification-outbox/stats    # Get statistics
GET  /api/v1/notification-outbox/{id}     # Get single entry
POST /api/v1/notification-outbox/{id}/retry # Retry failed entry
DELETE /api/v1/notification-outbox/{id}   # Delete entry
```

**Permissions Required:**
- `integrations:notifications:read` for GET endpoints
- `integrations:notifications:write` for POST (retry)
- `integrations:notifications:delete` for DELETE

### Event History API (TODO)

```
GET /api/v1/notification-events           # List archived events
GET /api/v1/notification-events/stats     # Get statistics
GET /api/v1/notification-events/{id}      # Get event with send results
```

## Notification Providers

### Provider Factory Pattern

```go
// internal/infra/notification/client.go

type Client interface {
    Send(ctx context.Context, msg Message) (*SendResult, error)
    TestConnection(ctx context.Context) (*SendResult, error)
    Provider() string
}

func (f *ClientFactory) CreateClient(config Config) (Client, error) {
    switch config.Provider {
    case ProviderSlack:    return NewSlackClient(config)
    case ProviderTeams:    return NewTeamsClient(config)
    case ProviderTelegram: return NewTelegramClient(config)
    case ProviderEmail:    return NewEmailClient(config)
    case ProviderWebhook:  return NewWebhookClient(config)
    }
}
```

### Provider Comparison

| Provider | Config | Format | Special Features |
|----------|--------|--------|------------------|
| **Slack** | Webhook URL | Slack Blocks + Attachments | Colored sidebars, emoji indicators |
| **Teams** | Webhook URL | Adaptive Cards | Container styles (attention/warning) |
| **Telegram** | Bot Token + Chat ID | Markdown + Inline Buttons | URL buttons, markdown escaping |
| **Email** | SMTP config | HTML with CSS | TLS/STARTTLS, multiple recipients |
| **Webhook** | Custom URL | JSON payload | Flexible, any endpoint |

### Severity Indicators

| Severity | Color | Emoji | Teams Style |
|----------|-------|-------|-------------|
| Critical | `#dc2626` (Red) | :rotating_light: | attention |
| High | `#ea580c` (Orange) | :warning: | warning |
| Medium | `#ca8a04` (Yellow) | :large_yellow_circle: | accent |
| Low | `#2563eb` (Blue) | :large_blue_circle: | good |

## Security

### Credentials Encryption

All notification credentials are encrypted at rest using AES-256-GCM:

```go
// internal/app/notification_service.go

credentials, err := s.credentialDecrypt(intg.CredentialsEncrypted())
```

**Environment Variable:** `APP_ENCRYPTION_KEY` (32-byte key, hex or base64 format)

### Rate Limiting

Test notifications are rate-limited to prevent spam:

```go
const testNotificationRateLimit = 30 * time.Second
```

## Event Types

Dynamic event types stored as JSONB:

```go
// internal/domain/integration/notification_extension.go

type EventType string

const (
    EventTypeFindings  EventType = "findings"
    EventTypeExposures EventType = "exposures"
    EventTypeScans     EventType = "scans"
    EventTypeAlerts    EventType = "alerts"
)
```

Integrations can filter which event types they receive.

## Wiring in Main

```go
// cmd/server/main.go

// Initialize repositories
notificationOutboxRepo := postgres.NewNotificationOutboxRepository(db)
notificationEventRepo := postgres.NewNotificationEventRepository(db)
integrationNotificationExtRepo := postgres.NewIntegrationNotificationExtensionRepository(db, integrationRepo)

// Initialize notification service
notificationService := app.NewNotificationService(
    notificationOutboxRepo,
    notificationEventRepo,
    integrationNotificationExtRepo,
    credentialsEncryptor.DecryptString,
    log.Logger,
)

// Initialize scheduler
notificationScheduler := app.NewNotificationScheduler(
    notificationService,
    app.DefaultNotificationSchedulerConfig(),
    log,
)

// Wire up to other services
vulnerabilityService.SetNotificationService(db.DB, notificationService)
exposureService.SetNotificationService(db.DB, notificationService)
```

## Deprecation Notice

### notification_history (REMOVED)

The `notification_history` table has been **removed** in migration `000075_drop_notification_history`. It was replaced by the `notification_events` table which provides:

- **Event-centric view**: One record per notification event (vs per-integration)
- **JSONB send_results**: All integration results in one place
- **Better querying**: Filter by event type, aggregate, status
- **Cleaner architecture**: Outbox = Queue, Events = Archive

All related code (repository, service methods, API endpoints) has been removed.

## Related Documents

- [Clean Architecture](./clean-arch.md)
- [Security Best Practices](../SECURITY.md)
