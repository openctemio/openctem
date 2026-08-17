package handler

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/ctemcycle"
	"github.com/openctemio/api/pkg/domain/shared"
)

// metricKeyOrder is the stable order metrics are emitted in the trend
// series so the UI renders a consistent set of lines.
var metricKeyOrder = []string{
	ctemcycle.MetricMTTRHours,
	ctemcycle.MetricFindingsOpened,
	ctemcycle.MetricFindingsResolved,
	ctemcycle.MetricPClassChurn,
	ctemcycle.MetricValidationCoverage,
	ctemcycle.MetricScopeDriftSize,
}

// GetMetrics returns the persisted metrics for one cycle. When a closed
// cycle has none yet (e.g. it was closed before this feature shipped),
// they are computed and persisted lazily so historical cycles are never
// empty.
func (h *CTEMCycleHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	if h.metrics == nil {
		apierror.InternalServerError("metrics not available").WriteJSON(w)
		return
	}
	tid, cid, ok := h.parseTenantCycle(w, tenantID, id)
	if !ok {
		return
	}

	// Confirm the cycle belongs to the tenant and learn its status.
	var status string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT status FROM ctem_cycles WHERE id = $1 AND tenant_id = $2`,
		id, tenantID,
	).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		apierror.NotFound("cycle not found").WriteJSON(w)
		return
	}
	if err != nil {
		h.logger.Error("ctem cycle metrics: load status", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	stored, err := h.metrics.Get(r.Context(), tid, cid)
	if err != nil {
		h.logger.Error("ctem cycle metrics: get", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	// Lazy compute-on-read for closed cycles with no metrics yet.
	computed := false
	if len(stored) == 0 && status == "closed" {
		h.persistMetrics(r.Context(), tenantID, id)
		stored, err = h.metrics.Get(r.Context(), tid, cid)
		if err != nil {
			h.logger.Error("ctem cycle metrics: get after lazy compute", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		computed = len(stored) > 0
	}

	values := make(map[string]float64, len(stored))
	for _, m := range stored {
		if _, seen := values[m.MetricType]; !seen {
			values[m.MetricType] = m.Value
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cycle_id":        id,
		"status":          status,
		"computed_lazily": computed,
		"metrics":         stored,
		"values":          values,
	})
}

// trendSeriesPoint is one (cycle, value) sample in a metric's series.
type trendSeriesPoint struct {
	CycleID  string  `json:"cycle_id"`
	Name     string  `json:"name"`
	ClosedAt string  `json:"closed_at"`
	Value    float64 `json:"value"`
}

// MetricsTrend returns, across the tenant's closed cycles, each metric's
// series over time plus a transparent maturity breakdown. The maturity
// score is never a single opaque number — every weighted component is
// returned with its raw value, sub-score, weight and contribution (see
// ctemcycle.ComputeMaturity).
func (h *CTEMCycleHandler) MetricsTrend(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	if h.metrics == nil {
		apierror.InternalServerError("metrics not available").WriteJSON(w)
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	cycles, err := h.metrics.ListClosedForTenant(r.Context(), tid)
	if err != nil {
		h.logger.Error("ctem cycle metrics: trend list", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	// Per-metric series over time (cycles are already ordered ascending).
	series := make(map[string][]trendSeriesPoint, len(metricKeyOrder))
	for _, key := range metricKeyOrder {
		series[key] = make([]trendSeriesPoint, 0, len(cycles))
	}
	summaries := make([]map[string]any, 0, len(cycles))
	for _, c := range cycles {
		closedAt := c.ClosedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		for _, key := range metricKeyOrder {
			series[key] = append(series[key], trendSeriesPoint{
				CycleID:  c.CycleID.String(),
				Name:     c.Name,
				ClosedAt: closedAt,
				Value:    c.Value(key),
			})
		}
		summaries = append(summaries, map[string]any{
			"cycle_id":  c.CycleID.String(),
			"name":      c.Name,
			"closed_at": closedAt,
			"metrics":   c.Metrics,
		})
	}

	maturity := ctemcycle.ComputeMaturity(cycles)

	writeJSON(w, http.StatusOK, map[string]any{
		"cycles_analyzed": len(cycles),
		"cycles":          summaries,
		"series":          series,
		"maturity":        maturity,
	})
}

// persistMetrics computes and persists a cycle's metrics best-effort.
// Errors are logged, never surfaced — callers must not depend on it
// succeeding (Close must still close; GetMetrics still returns what is
// stored).
func (h *CTEMCycleHandler) persistMetrics(ctx context.Context, tenantID, cycleID string) {
	if h.metrics == nil {
		return
	}
	tid, cid, ok := h.parseIDs(tenantID, cycleID)
	if !ok {
		h.logger.Warn("ctem cycle metrics: bad ids; skipping compute",
			"tenant_id", sanitizeLogField(tenantID), "cycle_id", sanitizeLogField(cycleID))
		return
	}
	set, err := h.metrics.Compute(ctx, tid, cid)
	if err != nil {
		h.logger.Warn("ctem cycle metrics: compute failed", "cycle_id", sanitizeLogField(cycleID), "error", err)
		return
	}
	if err := h.metrics.UpsertBatch(ctx, tid, cid, set); err != nil {
		h.logger.Warn("ctem cycle metrics: persist failed", "cycle_id", sanitizeLogField(cycleID), "error", err)
	}
}

// parseTenantCycle parses both ids, writing a 500 and returning ok=false
// on failure (a malformed tenant/cycle id at this layer is unexpected).
func (h *CTEMCycleHandler) parseTenantCycle(
	w http.ResponseWriter, tenantID, cycleID string,
) (shared.ID, shared.ID, bool) {
	tid, cid, ok := h.parseIDs(tenantID, cycleID)
	if !ok {
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
	return tid, cid, ok
}

func (h *CTEMCycleHandler) parseIDs(tenantID, cycleID string) (shared.ID, shared.ID, bool) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, false
	}
	cid, err := shared.IDFromString(cycleID)
	if err != nil {
		return shared.ID{}, shared.ID{}, false
	}
	return tid, cid, true
}
