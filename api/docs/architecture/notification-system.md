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

**Permissions Required** (every route also needs `integrations:manage`):
- `integrations:notifications:read` for GET endpoints
- `integrations:notifications:write` for POST (retry)
- `integrations:notifications:delete` for DELETE

`GET /api/v1/integrations/{id}/notification-events` (a channel's delivery
history) needs `integrations:manage`.

**Why channel managers only:** the outbox gets a row for every event, whether
or not a channel is configured: new findings (message, asset id, owner name
and email), new assets, exposures, SLA and approval events, for the whole
organization and without data scope. Members and viewers hold
`integrations:notifications:read` for their own in-app notices; before
research doc 15 (L-03) that also opened this stream to them. Whoever holds
`integrations:manage` already decides which of these events leave for Slack,
Teams or a webhook, so the history shows them nothing new. The web console
hides *View events* and *Queue* without that permission.

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

### Untrusted message text

Titles, bodies and fields often carry finding text that a scan target controls.
Every client returned by `ClientFactory.CreateClient` sends `Message.Cleaned()`
(`internal/infra/notifier/client.go`). That removes control, bidi-control and
zero-width characters (Trojan Source: an RLO override would make a message
display something other than what it says) and caps lengths: 300 characters
for a title, 2,000 for a field and 20,000 for a body. Each provider then
escapes its own markup: Slack mrkdwn (`&`, `<`, `>`, so no `<!channel>` or
disguised links), Telegram markdown, and `html/template` for e-mail. The
generic webhook sends JSON. See RFC-040 §5.4.

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

The registry clients render is `integration.AllEventTypes()` (served by
`GET /api/v1/me/event-types`). A channel's severity filter applies only to
events whose severity describes a finding; `integration.SeverityFilterApplies`
lists the exempt ones (approval events, `new_asset`, `sensor.offline`), whose
severity is a constant chosen by the emitter. The outbox honours that list when
it matches an entry to a channel.

**Only emitted types are listed** (settings plan P0-08). A type goes into
`AllEventTypes()` together with its producer, which is code that enqueues or
sends a notification with that type. `tests/unit/event_type_producer_test.go`
fails on a listed type nothing emits.

These types had no producer and were removed from the catalog:

- `security_alert`, which was on by default;
- `system_error`, `asset_changed`, `asset_deleted`;
- `scan_started`, `scan_completed`, `scan_failed`;
- `finding_confirmed`, `finding_triaged`, `exposure_resolved`.

The "System Events" and "Scan Events" groups went with them. Every remaining
type belongs to a module, so a tenant with no optional modules is offered no
types. If a subscription saved earlier still lists a removed type, that entry
never matches anything. To bring a type back, add its producer in the same
change.

### Sensor events

| Event | Emitted by | When |
|---|---|---|
| `sensor.offline` | `SensorHealthController` (`internal/infra/controller/sensor_health.go`) | A tenant sensor's health goes `online` -> `offline` (no heartbeat for 90s). Once per transition: a sensor that stays offline is not re-announced on later ticks; one that reconnects and drops again is a new event. Severity `high`. Opt-in (not in the defaults). |

The same transition writes the `sensor.disconnected` audit event. Platform
sensors (no tenant) produce neither. `sensor.error` exists in the `event_types`
catalog but has no emitter: nothing in the platform sets a sensor's health to
`error`, so there is no transition to announce.

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

## In-App Inbox (user notifications)

Separate from the outbox above, `NotificationService.Notify`
(`internal/app/integration/notification.go`) stores one row per event in
`notifications` with an audience: `user` (one user), `group` (the members of
one group) or `all` (every member of the tenant). Read state and preferences
are per user (`notification_reads`, `notification_state`,
`notification_preferences`).

### Who sees a notification

One rule decides it, applied in three places so they never disagree:

| Path | Where |
|------|-------|
| Inbox list `GET /api/v1/notifications` | `NotificationRepository.List` |
| Unread badge `GET /api/v1/notifications/unread-count` | `NotificationRepository.UnreadCount` |
| Real-time push over the WebSocket | `NotificationRepository.ListRecipients` |

A user sees a notification when they are in its audience **and** their
preferences allow it:

- `in_app_enabled = false` hides every in-app notification;
- a type in `muted_types` is hidden;
- a severity below `min_severity` is hidden (critical > high > medium > low > info).

A user with no preferences row gets the defaults (everything shown). The SQL
predicate (`preferenceFilter`) is the twin of `notification.Preferences.Allows`;
`tests/integration/notification_ws_isolation_test.go` checks every combination
against it.

`email_digest` (`none` / `daily` / `weekly`) is stored but no digest sender
exists yet, and no in-app notification is emailed individually, so the in-app
filters above have no email path to apply to.

### Real-time push

Each recipient gets the notification on their own channel,
`user:{tenant_id}:{user_id}` (`notification.UserChannel`). The hub lets a
connection subscribe only to the channel of the user and tenant it
authenticated as, and delivers a user channel only to that user's
connections. Notifications are never sent on `tenant:{id}` (every member can
watch it) or `group:{id}`. The UI's notification bell subscribes to its user
channel.

The connection is opened on the UI's own origin and authenticated by the
session cookie through the tenant gates (SSO enforcement, organization IP
allowlist, active membership) and the Origin allowlist. A suspended or
removed member therefore gets no stream, and an open socket is closed when its session is
signed out or revoked, when the member is suspended, removed or changes
role, and at its token's expiry ([RFC-045](../rfcs/RFC-045-websocket-auth.md)),
so a stream never outlives the access that opened it. See
[authorization-matrix.md](./authorization-matrix.md#real-time-websocket-apiv1ws).

## Deprecation Notice

### notification_history (REMOVED)

The `notification_history` table has been **removed** in migration `000075_drop_notification_history`. It was replaced by the `notification_events` table which provides:

- **Event-centric view**: One record per notification event (vs per-integration)
- **JSONB send_results**: All integration results in one place
- **Better querying**: Filter by event type, aggregate, status
- **Cleaner architecture**: Outbox = Queue, Events = Archive

All related code (repository, service methods, API endpoints) has been removed.

### Outbound webhooks `/api/v1/webhooks` (REMOVED)

`/api/v1/webhooks` stored endpoint URLs and signing secrets, but no worker
ever delivered to them. Nothing was sent, and nothing wrote
`webhook_deliveries`. Owner decision B9 removed the feature: the routes,
handler, service, repository and domain package are gone. Migration `001032`
does three things:

- archives and removes the `integrations:webhooks:*` permissions and their role
  grants (the down migration restores them);
- deprecates the `integrations.webhooks` module toggle;
- keeps the `webhooks` and `webhook_deliveries` tables untouched (no data is
  destroyed).

For outbound delivery, use a notification channel (Slack, Teams, Telegram,
email, or a custom webhook channel, all sent through the outbox) or the SIEM
integration. Inbound webhooks (`/api/v1/webhooks/incoming/*`, HMAC-verified)
are unaffected. `tests/unit/outbound_webhooks_removed_test.go` keeps the
permissions and the module toggle from coming back without a sender.

## Related Documents

- [Clean Architecture](./clean-arch.md)
- [Security Best Practices](../SECURITY.md)

## Integration safety rules (all categories)

- **Request metadata is an allowlist.** A create or update may only set the
  non-secret keys `hec_url`, `index`, `sourcetype` and `channel_name` (string,
  at most 2048 characters). Every other metadata key is written by the server
  (chat ids, SMTP settings, sync state), and a request that names one is
  refused with 400. Secrets go in the encrypted credentials field, never in
  metadata (`internal/app/integration/hardening.go`).
- **Disabled stays disabled.** A test, a sync or a read (listing an SCM
  integration's repositories) never moves a disabled integration back to
  connected or error; only `POST /integrations/{id}/enable` does. Listing the
  repositories of a disabled SCM integration is refused without calling the
  provider.
- **Credentials do not follow a new host.** Changing `base_url` to another
  scheme, host or port while credentials are stored requires new credentials
  in the same request (400 otherwise), so a manager cannot point Jira or SCM at
  their own server and receive the stored token.
