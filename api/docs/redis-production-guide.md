# Redis Production Deployment Guide

This guide covers the API's Redis configuration for production: what the API
requires, how it uses Redis, and how to tune and troubleshoot it. The operator
guide for a whole installation is at
[docs.openctem.io/configuration](https://docs.openctem.io/configuration/).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Configuration](#configuration)
3. [Security](#security)
4. [High Availability](#high-availability)
5. [Authentication rate limits](#authentication-rate-limits)
6. [Monitoring](#monitoring)
7. [Performance Tuning](#performance-tuning)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### Redis Server Requirements

- Redis 6.0+ (for TLS support)
- Minimum 2GB RAM for production workloads
- SSD storage recommended for persistence

### Go Application Requirements

- Go 1.26+
- `github.com/redis/go-redis/v9`

## Configuration

### Environment Variables

```bash
# Required for production
REDIS_HOST=redis.example.com       # Private DNS name or IP
REDIS_PORT=6379
REDIS_PASSWORD=<strong-password>   # Required in production
REDIS_DB=0

# Connection Pool (tune based on load)
REDIS_POOL_SIZE=25                 # Max connections
REDIS_MIN_IDLE_CONNS=5            # Keep warm connections

# Timeouts
REDIS_DIAL_TIMEOUT=5s
REDIS_READ_TIMEOUT=3s
REDIS_WRITE_TIMEOUT=3s

# TLS (required in production)
REDIS_TLS_ENABLED=true
REDIS_TLS_SKIP_VERIFY=false       # Must be false in production
REDIS_TLS_CA_FILE=                # Optional: CA bundle for a private CA
REDIS_TLS_CERT_FILE=              # Optional: client certificate (mutual TLS)
REDIS_TLS_KEY_FILE=

# Retry Configuration
REDIS_MAX_RETRIES=3
REDIS_MIN_RETRY_DELAY=100ms
REDIS_MAX_RETRY_DELAY=3s
```

### Production validation

With `APP_ENV=production` the API refuses to start unless `REDIS_PASSWORD` is
set and at least 32 characters, `REDIS_TLS_ENABLED=true`,
`REDIS_TLS_SKIP_VERIFY=false`, `REDIS_POOL_SIZE` is between 10 and 500, and the
dial and read timeouts are at least 1s (`validateProductionRedis` in
`internal/config/config.go`).

### Pool Size Guidelines

| Concurrent Users | Pool Size | Min Idle |
|-----------------|-----------|----------|
| < 100           | 10        | 2        |
| 100 - 1,000     | 25        | 5        |
| 1,000 - 10,000  | 50        | 10       |
| > 10,000        | 100       | 20       |

Formula: `PoolSize = (Concurrent Requests × Avg Redis Calls per Request) / 10`

## Security

### TLS Configuration

**Redis Server (redis.conf):**
```
tls-port 6379
port 0
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-auth-clients yes
```

**Application:**
```bash
REDIS_TLS_ENABLED=true
REDIS_TLS_SKIP_VERIFY=false
```

### Password Requirements

- Minimum 32 characters
- Keep it in a secrets manager, not in the repository
- Rotate passwords periodically

```bash
# Generate secure password
openssl rand -base64 32
```

### Network Security

1. **Private Network**: Redis should only be accessible from internal network
2. **Firewall Rules**: Allow only application servers to connect
3. **VPC/Security Groups**: Restrict to specific CIDR ranges

### Redis ACL (Redis 6+)

Create dedicated user for the application:

```redis
ACL SETUSER openctem on >strongpassword openctem:* +@all -@dangerous
```

## High Availability

The API connects to a **single standalone Redis endpoint**; Redis Sentinel and
Redis Cluster are not supported by the client today. For availability, use a
managed Redis service that fails over behind one endpoint, and size it so a
restart is short: the API degrades gracefully while Redis is down (caches fall
back to the database, rate limits fall back to per-replica memory, see below).

## Authentication rate limits

The public sign-in surface is rate limited per client IP (and, for the second
login step, per challenge). The budgets are counted in Redis, so every API
replica spends the same budget: with in-memory limits a client spread across N
replicas would get N times the budget.

| Bucket (store scope) | Routes | Budget |
|---|---|---|
| `auth:login` | `/auth/login`, OAuth callback, `/auth/sso/*`, `/auth/saml/*`, back-channel logout | 5/min per IP |
| `auth:register` | `/auth/register`, `/auth/create-first-team` | 3/min per IP |
| `auth:password` | `/auth/forgot-password`, `/auth/reset-password` (also redeems set-password links), `/auth/verify-email` | 3/min per IP |
| `auth:token` | `/auth/token`, `/auth/refresh` | 20/min per IP |
| `auth:mfa`, `auth:mfa-ip` | `/auth/mfa/verify`, `/auth/mfa/enroll/*` | 10/min per challenge, 30/min per IP |
| `account-2fa:login`, `account-2fa:password` | `/users/me/2fa/setup`, `/enable` / `/disable`, `/recovery-codes` | 5/min, 3/min per IP |
| `account-password:password` | `/users/me/change-password` | 3/min per IP |
| `step-up:login` | `POST /auth/step-up` | 5/min per IP |
| `console:login`, `console:password`, `console:token` | admin console `/admin/auth/session`, `/admin/auth/mfa` / `/password` / `/idp/start`, `/idp/callback` | 5/min, 3/min, 20/min per IP |
| `invitation:token` | `/invitations/lookup`, `/accept`, `/decline`, `/accept-with-refresh` (token in the body), and the deprecated `/invitations/{token}/...` aliases | 20/min per IP |

`/auth/providers` is not in these buckets: it is a config read the UI makes on
many screens and uses the general API limiter (`RATE_LIMIT_*`), so reading it
never spends the login budget.

Keys are `authrl:<scope>:<bucket>:<key>` (sorted sets, sliding one-minute
window, expiring after a minute of inactivity). Each scope is a separate
budget: the console sign-in does not spend the tenant login budget.

**Redis unavailable.** Sign-in stays available: when a Redis call fails the
request is checked against the replica's own in-memory bucket instead (the
same budgets, per replica), and the API logs
`auth rate limit: shared store failed, using in-memory limit` at WARN. An
outage therefore weakens the limit to per-replica for its duration; it never
fails sign-in closed or open. Without Redis wired at all (single-instance dev,
tests) the limits are in-memory only.

## Monitoring

### Prometheus metrics

The Redis client records metrics under the `openctem_redis_` prefix, exposed on
the API's `/metrics` endpoint (bearer token `METRICS_TOKEN`, see
[Monitoring and alerting](operations/monitoring.md)):

| Metric | Description | Suggested alert |
|--------|-------------|-----------------|
| `openctem_redis_operation_duration_seconds` | Operation latency (histogram) | p99 > 100ms |
| `openctem_redis_operations_total` | Operations | - |
| `openctem_redis_operation_errors_total` | Errors | > 10/min |
| `openctem_redis_cache_hits_total`, `openctem_redis_cache_misses_total` | Cache hits and misses | hit rate < 80% |
| `openctem_redis_ratelimit_allowed_total`, `openctem_redis_ratelimit_denied_total` | Rate-limit decisions | spikes |
| `openctem_redis_pool_*` (`hits`, `misses`, `timeouts`, `total_connections`, `idle_connections`, `stale_connections`) | Connection pool statistics | timeouts increasing |

The pool gauges are filled by `redis.StartPoolStatsCollector`
(`internal/infra/redis/metrics.go`); they stay at zero unless the server starts
that collector.

### Health check

`GET /ready` pings the database and Redis and answers 503 when either check
fails; use it as the readiness probe. `GET /health` is liveness only.

### Logging

Use `LOG_LEVEL=debug` to troubleshoot and `LOG_LEVEL=info` in production.

## Performance Tuning

### Connection Pool Optimization

```bash
# High-throughput configuration
REDIS_POOL_SIZE=100        # Increase for high concurrency
REDIS_MIN_IDLE_CONNS=20    # Keep connections warm
```

### Redis Server Tuning

```conf
# redis.conf

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Connections
maxclients 10000
timeout 0
tcp-keepalive 300

# Persistence (if needed)
save 900 1
save 300 10
save 60 10000

# Performance
io-threads 4
io-threads-do-reads yes
```

### Application Best Practices

1. **Use Pipelining for Batch Operations**
   ```go
   // Good: Pipeline multiple operations
   results, err := cache.MGet(ctx, "key1", "key2", "key3")

   // Bad: Individual calls
   r1, _ := cache.Get(ctx, "key1")
   r2, _ := cache.Get(ctx, "key2")
   ```

2. **Choose Appropriate TTLs**
   ```go
   // Session: Match JWT expiry
   tokenStore.StoreSession(ctx, userID, sessionID, data, 24*time.Hour)

   // Cache: Based on data freshness requirements
   cache.SetWithTTL(ctx, key, value, 5*time.Minute)
   ```

3. **Use Key Prefixes**
   ```go
   // Organized key structure
   userCache := redis.NewCache[User](client, "user", time.Hour)     // user:123
   sessionCache := redis.NewCache[Session](client, "sess", time.Hour) // sess:abc
   ```

## Troubleshooting

### Common Issues

#### Connection Refused

```
Error: dial tcp: connect: connection refused
```

**Solutions:**
1. Verify Redis is running: `redis-cli ping`
2. Check host/port configuration
3. Verify firewall rules
4. Check TLS settings match server configuration

#### Pool Exhaustion

```
Error: redis: connection pool timeout
```

**Solutions:**
1. Increase `REDIS_POOL_SIZE`
2. Check for connection leaks (missing Close calls)
3. Reduce operation timeouts
4. Add circuit breaker for failing dependencies

#### TLS Handshake Failure

```
Error: tls: failed to verify certificate
```

**Solutions:**
1. Verify certificate chain is complete
2. Check certificate expiration
3. Ensure CA certificate is trusted
4. Verify hostname matches certificate CN/SAN

#### High Latency

**Diagnosis:**
```bash
redis-cli --latency-history
redis-cli info stats | grep instantaneous_ops
```

**Solutions:**
1. Check network latency to Redis
2. Monitor Redis slowlog: `redis-cli slowlog get 10`
3. Optimize hot keys

### Debug Commands

```bash
# Check connection
redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD ping

# Monitor commands in real-time
redis-cli monitor

# Check memory usage
redis-cli info memory

# Find big keys
redis-cli --bigkeys

# Check slowlog
redis-cli slowlog get 10
```

## Deployment Checklist

Before going to production, verify:

- [ ] TLS enabled (`REDIS_TLS_ENABLED=true`)
- [ ] Strong password set (`REDIS_PASSWORD` >= 32 chars)
- [ ] TLS verification enabled (`REDIS_TLS_SKIP_VERIFY=false`)
- [ ] Connection pool sized appropriately
- [ ] Timeouts configured
- [ ] Retry logic configured
- [ ] Metrics exposed and monitored
- [ ] Readiness probe on `/ready`
- [ ] Alerts configured for key metrics
- [ ] Backup strategy in place (if using persistence)
- [ ] Network security configured (firewall, VPC)
- [ ] Redis ACL configured (Redis 6+)
- [ ] Load tested with expected traffic

## Quick Reference

### Environment Variables Summary

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_HOST` | Yes | localhost | Redis server host |
| `REDIS_PORT` | Yes | 6379 | Redis server port |
| `REDIS_PASSWORD` | Prod | "" | Authentication password (32+ characters in production) |
| `REDIS_DB` | No | 0 | Database number |
| `REDIS_POOL_SIZE` | No | 10 | Connection pool size |
| `REDIS_MIN_IDLE_CONNS` | No | 2 | Minimum idle connections |
| `REDIS_DIAL_TIMEOUT` | No | 5s | Connection timeout |
| `REDIS_READ_TIMEOUT` | No | 3s | Read operation timeout |
| `REDIS_WRITE_TIMEOUT` | No | 3s | Write operation timeout |
| `REDIS_TLS_ENABLED` | Prod | false | Enable TLS |
| `REDIS_TLS_SKIP_VERIFY` | No | false | Skip cert verification (refused in production) |
| `REDIS_TLS_CA_FILE` | No | "" | CA bundle |
| `REDIS_TLS_CERT_FILE`, `REDIS_TLS_KEY_FILE` | No | "" | Client certificate for mutual TLS |
| `REDIS_MAX_RETRIES` | No | 3 | Max retry attempts |
| `REDIS_MIN_RETRY_DELAY` | No | 100ms | Min retry backoff |
| `REDIS_MAX_RETRY_DELAY` | No | 3s | Max retry backoff |
