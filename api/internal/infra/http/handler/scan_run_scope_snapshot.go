package handler

// The scope snapshot of a scan run (RFC-065 §9): the entries that covered
// the run's targets when it started, the programs they belong to with their
// attestation, and the SHA-256 of that canonical body.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunScopeSnapshots reads a run's snapshot (*postgres.ScopeSnapshotRepository).
type RunScopeSnapshots interface {
	GetForRun(ctx context.Context, tenantID, runID shared.ID) (*postgres.RunSnapshot, error)
}

// SetScopeSnapshots wires GET /scan-runs/{id}/scope-snapshot.
func (h *ScanWorkflowHandler) SetScopeSnapshots(s RunScopeSnapshots) { h.scopeSnapshots = s }

// RunScopeSnapshotResponse is a run's scope snapshot.
type RunScopeSnapshotResponse struct {
	SHA256  string          `json:"sha256"`
	TakenAt time.Time       `json:"taken_at"`
	Body    json.RawMessage `json:"body" swaggertype:"object"`
}

// GetRunScopeSnapshot handles GET /api/v1/scan-runs/{id}/scope-snapshot
// @Summary      Scope snapshot of a run
// @Description  The scope the run relied on when it started (RFC-065): the entries that covered its targets (with their authorization source, program and tier), the programs they belong to with their accepted terms hash and program exclusions, and the SHA-256 of the canonical body. Needs scans:read and either scope:read or programs:read; a run the caller may not see answers 404, as does a run without a snapshot.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Run ID"
// @Success      200  {object}  RunScopeSnapshotResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/scope-snapshot [get]
func (h *ScanWorkflowHandler) GetRunScopeSnapshot(w http.ResponseWriter, r *http.Request) {
	if h.scopeSnapshots == nil {
		apierror.NotFound("Scope snapshot").WriteJSON(w)
		return
	}
	if !h.guardRun(w, r) {
		return
	}
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.NotFound("Scope snapshot").WriteJSON(w)
		return
	}
	runID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Scope snapshot").WriteJSON(w)
		return
	}
	snap, err := h.scopeSnapshots.GetForRun(r.Context(), tenantID, runID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Scope snapshot").WriteJSON(w)
			return
		}
		apierror.InternalServerError("Scope snapshot read failed").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, RunScopeSnapshotResponse{SHA256: snap.SHA256, TakenAt: snap.TakenAt, Body: snap.Body})
}
