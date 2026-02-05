package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Pinger interface for health check dependencies.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	db    Pinger
	redis Pinger
}

// HealthHandlerOption configures the health handler.
type HealthHandlerOption func(*HealthHandler)

// WithDatabase adds database health check.
func WithDatabase(db Pinger) HealthHandlerOption {
	return func(h *HealthHandler) {
		h.db = db
	}
}

// WithRedis adds Redis health check.
func WithRedis(redis Pinger) HealthHandlerOption {
	return func(h *HealthHandler) {
		h.redis = redis
	}
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(opts ...HealthHandlerOption) *HealthHandler {
	h := &HealthHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// Health handles the /health endpoint (liveness probe).
// @Summary      Health check
// @Description  Returns the health status of the service (liveness probe)
// @Tags         Health
// @Produce      json
// @Success      200  {object}  HealthResponse
// @Router       /health [get]
func (h *HealthHandler) Health(w http.ResponseWriter, _ *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ReadyResponse represents the readiness check response.
type ReadyResponse struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]CheckResult `json:"checks,omitempty"`
}

// CheckResult represents a single health check result.
type CheckResult struct {
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Ready handles the /ready endpoint (readiness probe).
// @Summary      Readiness check
// @Description  Checks all dependencies and returns 503 if any are unhealthy
// @Tags         Health
// @Produce      json
// @Success      200  {object}  ReadyResponse
// @Failure      503  {object}  ReadyResponse
// @Router       /ready [get]
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]CheckResult)
	allHealthy := true

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check database
	if h.db != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := h.checkDependency(ctx, "database", h.db)
			mu.Lock()
			checks["database"] = result
			if result.Status != "ok" {
				allHealthy = false
			}
			mu.Unlock()
		}()
	}

	// Check Redis
	if h.redis != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := h.checkDependency(ctx, "redis", h.redis)
			mu.Lock()
			checks["redis"] = result
			if result.Status != "ok" {
				allHealthy = false
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	status := "ready"
	statusCode := http.StatusOK
	if !allHealthy {
		status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	}

	response := ReadyResponse{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Checks:    checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

// checkDependency pings a dependency and returns the result.
func (h *HealthHandler) checkDependency(ctx context.Context, name string, pinger Pinger) CheckResult {
	start := time.Now()
	err := pinger.Ping(ctx)
	duration := time.Since(start)

	if err != nil {
		return CheckResult{
			Status:   "error",
			Duration: duration.String(),
			Error:    err.Error(),
		}
	}

	return CheckResult{
		Status:   "ok",
		Duration: duration.String(),
	}
}
