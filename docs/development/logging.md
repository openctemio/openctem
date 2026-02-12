# Logging Best Practices

## Overview

OpenCTEM uses Go's standard library `log/slog` for structured logging. The logger is configured in `pkg/logger/` and supports:

- **Structured logging** with key-value pairs
- **Log level filtering** (debug, info, warn, error)
- **Sensitive data masking** (passwords, tokens, etc.)
- **Log sampling** for high-traffic production environments
- **Configurable HTTP request logging** with skip paths

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `LOG_FORMAT` | `json` | Output format (json, text) |
| `LOG_SAMPLING_ENABLED` | `false` | Enable log sampling for production |
| `LOG_SAMPLING_THRESHOLD` | `100` | First N identical logs per second |
| `LOG_SAMPLING_RATE` | `0.1` | Sample rate after threshold (0.0-1.0) |
| `LOG_ERROR_SAMPLING_RATE` | `1.0` | Sample rate for errors (0.0-1.0) |
| `LOG_SKIP_HEALTH` | `true` | Skip health check endpoints |
| `LOG_SLOW_REQUEST_SECONDS` | `5` | Warn on slow requests |

### Production Settings

For production, enable sampling to reduce log volume:

```bash
# Enable sampling with defaults (100 logs/sec, then 10%)
LOG_SAMPLING_ENABLED=true

# Or customize
LOG_SAMPLING_ENABLED=true
LOG_SAMPLING_THRESHOLD=50      # First 50 identical logs/sec
LOG_SAMPLING_RATE=0.05         # Then 5%
LOG_ERROR_SAMPLING_RATE=1.0    # Always log errors
```

## Log Sampling

### Why Sampling?

In high-traffic production environments:
- Logging every request can overwhelm I/O
- Identical error messages can repeat thousands of times per second
- Log storage costs can become significant
- Too many logs make troubleshooting harder

### How Sampling Works

The sampling algorithm:
1. **First N logs** (threshold) are always logged
2. **After threshold**, logs are sampled at the configured rate
3. **Counters reset** every tick interval (default: 1 second)
4. **Errors** have a separate (usually higher) sampling rate

```
Example with Threshold=100, Rate=0.1:
- Log messages 1-100: All logged (100%)
- Log messages 101-1000: 10% logged (~90 messages)
- Total: ~190 logs instead of 1000 (81% reduction)
```

### Sampling by Level

Logs are grouped by level + message for deduplication:

```go
// These count as separate groups:
log.Info("user created", "id", 1)  // Group: "INFO:user created"
log.Info("user created", "id", 2)  // Same group (counts toward threshold)
log.Error("user created", "id", 3) // Group: "ERROR:user created" (different)
```

## HTTP Request Logging

### Skip Paths

By default, these paths are not logged:
- `/health`, `/healthz`
- `/ready`, `/readyz`
- `/live`, `/livez`
- `/metrics`
- `/api/v1/health`

This prevents health checks from flooding logs.

### Log Levels by Status

| Status Code | Log Level |
|-------------|-----------|
| 5xx | ERROR |
| 4xx | WARN |
| 2xx/3xx slow | WARN (if > SlowRequestThreshold) |
| 2xx/3xx | INFO |

### Slow Request Warning

Requests taking longer than `LOG_SLOW_REQUEST_SECONDS` are logged as warnings:

```json
{"level":"WARN","msg":"slow http request","method":"GET","path":"/api/v1/reports","duration":"6.2s","status":200}
```

## Sensitive Data Masking

These keys are automatically masked in logs:

- `password`, `secret`, `token`
- `authorization`, `api_key`, `private_key`
- `access_token`, `refresh_token`, `jwt`
- `cookie`, `session`
- `credit_card`, `ssn`, `email`

Partial matches also work (e.g., `db_password`, `jwt_secret`).

Example:
```go
log.Info("user login", "password", "secret123")
// Output: {"msg":"user login","password":"[REDACTED]"}
```

## Usage Examples

### Basic Usage

```go
import "github.com/openctemio/api/pkg/logger"

log := logger.NewProduction()

log.Info("user created", "id", 123, "email", "user@example.com")
log.Error("failed to process", "error", err)
```

### With Context

```go
// Add request context (request_id, user_id)
log := logger.FromContext(ctx)
log.Info("processing request")

// Or explicitly
log := logger.NewProduction().WithContext(ctx)
```

### With Error

```go
if err != nil {
    log.WithError(err).Error("operation failed")
}
```

### With Fields

```go
log.WithFields(map[string]any{
    "tenant_id": tenantID,
    "user_id":   userID,
    "action":    "delete",
}).Info("audit event")
```

## Best Practices

### DO

1. **Use structured logging** - Always use key-value pairs
   ```go
   log.Info("user created", "id", 123) // Good
   ```

2. **Log at appropriate levels**
   - `Error`: Requires immediate attention
   - `Warn`: Something unexpected but handled
   - `Info`: Important business events
   - `Debug`: Developer debugging info

3. **Include context** - Add request_id, tenant_id, user_id when available

4. **Enable sampling in production** - Reduce log volume and costs

5. **Monitor dropped logs** - Track sampling metrics if needed

### DON'T

1. **Don't log sensitive data** - Even masked, consider if it's necessary
   ```go
   log.Info("login", "password", pw) // Bad - even though masked
   ```

2. **Don't log in hot loops** - Move logs outside loops or use sampling

3. **Don't use debug level in production** - It bypasses sampling and adds overhead

4. **Don't log entire requests/responses** - Log relevant fields only

5. **Don't rely on log volume for metrics** - Use Prometheus instead

## Monitoring Dropped Logs

If you need to track how many logs are being dropped by sampling:

```go
import "github.com/openctemio/api/pkg/logger"

counter := logger.NewDroppedLogsCounter()

cfg := logger.SamplingConfig{
    Enabled:   true,
    Threshold: 100,
    Rate:      0.1,
    OnDropped: counter.Increment,
}

// Later, expose as Prometheus metric
droppedTotal := counter.Total()
```

## Performance Considerations

| Configuration | Logs/sec | I/O Impact | Notes |
|--------------|----------|------------|-------|
| No sampling | 1000+ | High | Not recommended for production |
| Threshold=100, Rate=0.1 | ~190 | Low | Good default |
| Threshold=50, Rate=0.05 | ~100 | Very Low | Aggressive, may miss issues |
| Skip health logs | -30% | Lower | Always recommended |

## Troubleshooting

### Too many logs in production

1. Enable sampling: `LOG_SAMPLING_ENABLED=true`
2. Lower threshold: `LOG_SAMPLING_THRESHOLD=50`
3. Lower rate: `LOG_SAMPLING_RATE=0.05`

### Missing important logs

1. Increase error rate: `LOG_ERROR_SAMPLING_RATE=1.0`
2. Increase threshold: `LOG_SAMPLING_THRESHOLD=200`
3. Check if path is in skip list

### Slow request performance

1. Check `SlowRequestThreshold` setting
2. Review slow endpoint for optimization
3. Consider async logging for very high throughput
