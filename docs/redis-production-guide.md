# Redis Production Deployment Guide

This guide covers deploying Redis integration for production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Configuration](#configuration)
3. [Security](#security)
4. [High Availability](#high-availability)
5. [Monitoring](#monitoring)
6. [Performance Tuning](#performance-tuning)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Redis Server Requirements

- Redis 6.0+ (for TLS support)
- Minimum 2GB RAM for production workloads
- SSD storage recommended for persistence

### Go Application Requirements

- Go 1.21+
- `github.com/redis/go-redis/v9`

## Configuration

### Environment Variables

```bash
# Required for production
REDIS_HOST=redis.internal          # Internal DNS or IP
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

# Retry Configuration
REDIS_MAX_RETRIES=3
REDIS_MIN_RETRY_DELAY=100ms
REDIS_MAX_RETRY_DELAY=3s
```

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
- Use secrets management (Vault, AWS Secrets Manager, etc.)
- Rotate passwords periodically

```bash
# Generate secure password
openssl rand -base64 32
```

### Network Security

1. **Private Network**: Redis should only be accessible from internal network
2. **Firewall Rules**: Allow only application servers to connect
3. **VPC/Security Groups**: Restrict to specific CIDR ranges

```bash
# Example: AWS Security Group
Inbound: TCP 6379 from app-security-group only
```

### Redis ACL (Redis 6+)

Create dedicated user for the application:

```redis
ACL SETUSER openctem on >strongpassword openctem:* +@all -@dangerous
```

## High Availability

### Redis Sentinel

For automatic failover, use Redis Sentinel:

```yaml
# docker-compose.yml
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}

  redis-slave:
    image: redis:7-alpine
    command: redis-server --slaveof redis-master 6379 --requirepass ${REDIS_PASSWORD} --masterauth ${REDIS_PASSWORD}

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/redis/sentinel.conf
```

**sentinel.conf:**
```
sentinel monitor mymaster redis-master 6379 2
sentinel auth-pass mymaster ${REDIS_PASSWORD}
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 60000
```

### Redis Cluster

For horizontal scaling (>100GB data or >100K ops/sec):

```bash
# Create 6-node cluster (3 masters, 3 replicas)
redis-cli --cluster create \
  node1:6379 node2:6379 node3:6379 \
  node4:6379 node5:6379 node6:6379 \
  --cluster-replicas 1
```

> **Note**: Current implementation supports standalone Redis only. For Sentinel/Cluster, additional code changes are required.

## Monitoring

### Prometheus Metrics

The Redis package exports metrics automatically. Ensure your application exposes them:

```go
import (
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/openctemio/api/internal/infra/redis"
)

// Start pool stats collector
cancel := redis.StartPoolStatsCollector(ctx, redisClient, 15*time.Second)
defer cancel()

// Expose metrics endpoint
http.Handle("/metrics", promhttp.Handler())
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `redis_operation_duration_seconds` | Operation latency | p99 > 100ms |
| `redis_operation_errors_total` | Error count | > 10/min |
| `redis_pool_total_connections` | Active connections | > 80% pool size |
| `redis_pool_timeouts_total` | Connection timeouts | Any increase |
| `redis_cache_hits_total` | Cache hits | Monitor ratio |
| `redis_cache_misses_total` | Cache misses | Hit rate < 80% |
| `redis_ratelimit_denied_total` | Rate limit denials | Monitor spikes |

### Grafana Dashboard

```json
{
  "panels": [
    {
      "title": "Redis Operations/sec",
      "expr": "rate(redis_operations_total[1m])"
    },
    {
      "title": "Redis Latency p99",
      "expr": "histogram_quantile(0.99, rate(redis_operation_duration_seconds_bucket[5m]))"
    },
    {
      "title": "Cache Hit Rate",
      "expr": "rate(redis_cache_hits_total[5m]) / (rate(redis_cache_hits_total[5m]) + rate(redis_cache_misses_total[5m]))"
    },
    {
      "title": "Pool Utilization",
      "expr": "redis_pool_total_connections / redis_pool_size"
    }
  ]
}
```

### Health Check Endpoint

```go
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    if err := h.redis.Ping(ctx); err != nil {
        w.WriteHeader(http.StatusServiceUnavailable)
        json.NewEncoder(w).Encode(map[string]string{
            "status": "unhealthy",
            "redis":  err.Error(),
        })
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "status": "healthy",
    })
}
```

### Logging

Enable debug logging for troubleshooting:

```bash
# Development
LOG_LEVEL=debug

# Production (reduce noise)
LOG_LEVEL=info
```

## Performance Tuning

### Connection Pool Optimization

```go
// High-throughput configuration
cfg := &config.RedisConfig{
    PoolSize:     100,        // Increase for high concurrency
    MinIdleConns: 20,         // Keep connections warm
    DialTimeout:  5*time.Second,
    ReadTimeout:  3*time.Second,
    WriteTimeout: 3*time.Second,
}
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
4. Consider Redis Cluster for sharding

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
- [ ] Health check endpoint working
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
| `REDIS_PASSWORD` | Prod | "" | Authentication password |
| `REDIS_DB` | No | 0 | Database number |
| `REDIS_POOL_SIZE` | No | 10 | Connection pool size |
| `REDIS_MIN_IDLE_CONNS` | No | 2 | Minimum idle connections |
| `REDIS_DIAL_TIMEOUT` | No | 5s | Connection timeout |
| `REDIS_READ_TIMEOUT` | No | 3s | Read operation timeout |
| `REDIS_WRITE_TIMEOUT` | No | 3s | Write operation timeout |
| `REDIS_TLS_ENABLED` | Prod | false | Enable TLS |
| `REDIS_TLS_SKIP_VERIFY` | No | false | Skip cert verification |
| `REDIS_MAX_RETRIES` | No | 3 | Max retry attempts |
| `REDIS_MIN_RETRY_DELAY` | No | 100ms | Min retry backoff |
| `REDIS_MAX_RETRY_DELAY` | No | 3s | Max retry backoff |
