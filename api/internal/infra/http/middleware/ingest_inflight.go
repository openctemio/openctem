package middleware

// In-flight bounds of sensor result uploads (research/191 R-1). Each v2/v3
// result request holds its body, and its decoded content, in memory while it
// is verified and accepted. The per-tenant cap (TenantConcurrencyLimiter)
// does not bound a shared sensor (it has no tenant) nor one sensor of a
// tenant taking every slot; the process-wide byte budget (V2ReadVerified)
// bounds them all but is sized from the replica's memory here.

import (
	"net/http"
	"os"
	"strconv"
	"strings"
)

// IngestSharedPoolKey is the key all shared sensors share in the shared
// pool limiter: shared sensors (no tenant) together never hold more result
// uploads than one organization.
const IngestSharedPoolKey = "shared-sensors"

// V2SensorInFlight refuses (429, Retry-After) a result upload when the
// sensor already has perSensor in flight, and, for a shared sensor, when the
// shared sensors together already have sharedPool in flight. sensor returns
// the authenticated sensor's key and whether it is a shared sensor ("" skips
// the check). Either limiter may be nil.
func V2SensorInFlight(perSensor, sharedPool *TenantConcurrencyLimiter, sensor func(*http.Request) (key string, shared bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, isShared := sensor(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !perSensor.TryAcquire(key) {
				writeV2RateLimited(w, 0)
				return
			}
			defer perSensor.Release(key)
			if isShared {
				if !sharedPool.TryAcquire(IngestSharedPoolKey) {
					writeV2RateLimited(w, 0)
					return
				}
				defer sharedPool.Release(IngestSharedPoolKey)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// cgroupMemoryFiles are where the container's memory limit is read (cgroup
// v2, then v1).
var cgroupMemoryFiles = []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}

// V2DecodeBudgetForMemory is the result-upload byte budget for a replica
// with memoryLimit bytes of memory (<= 0: unknown): a quarter of it, at most
// the default 1 GiB and at least 64 MiB, so uploads alone never take the
// memory the API needs for everything else.
func V2DecodeBudgetForMemory(memoryLimit int64) int64 {
	const (
		maxBudget int64 = 1 << 30
		minBudget int64 = 64 << 20
	)
	if memoryLimit <= 0 {
		return maxBudget
	}
	return min(max(memoryLimit/4, minBudget), maxBudget)
}

// ContainerMemoryLimit reads the process's cgroup memory limit; 0 when
// there is none or it cannot be read.
func ContainerMemoryLimit() int64 {
	for _, f := range cgroupMemoryFiles {
		raw, err := os.ReadFile(f) // #nosec G304 -- fixed system paths
		if err != nil {
			continue
		}
		return parseMemoryLimit(string(raw))
	}
	return 0
}

// parseMemoryLimit reads a cgroup limit file's content; "max" or a value
// that means "no limit" (v1 reports a huge number) is 0.
func parseMemoryLimit(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= 1<<60 {
		return 0
	}
	return n
}
