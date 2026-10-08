package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Who may see a run (research/62 §8). A scan run is read under scans:read in
// the caller's tenant. A run about a finding (kind retest) also exposes that
// finding's target and the check's output, so it needs findings:read and the
// finding in the caller's data scope; otherwise it is not found, exactly
// like a finding outside the scope.

// runFindingScope is the data-scope check of a finding (datascope.Enforcer).
type runFindingScope interface {
	Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
	AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error
}

// runReader reads one run of a tenant (*scanrun.Service).
type runReader interface {
	GetRun(ctx context.Context, tenantID, runID string) (*scanrundom.Run, error)
}

// SetRunReader replaces the run lookup the access check uses (tests).
func (h *ScanWorkflowHandler) SetRunReader(r runReader) { h.runLookup = r }

// SetFindingScope wires the data-scope check runs about a finding need.
func (h *ScanWorkflowHandler) SetFindingScope(s runFindingScope) { h.findingScope = s }

// runVisible reports whether the caller may see run.
func (h *ScanWorkflowHandler) runVisible(ctx context.Context, tenantID shared.ID, run *scanrundom.Run) bool {
	if !isFindingRun(run.KindOrDefault()) {
		return true
	}
	if !middleware.HasPermission(ctx, "findings:read") {
		return false
	}
	findingID, ok := subjectID(run.Subject, "finding_id")
	if !ok {
		return false
	}
	if h.findingScope == nil {
		return true
	}
	return h.findingScope.AssertFinding(ctx, tenantID, findingID) == nil
}

// guardRun answers 404 and returns false when the run in the path is not the
// caller's to see (another tenant's, or a run about a finding outside the
// caller's reach).
func (h *ScanWorkflowHandler) guardRun(w http.ResponseWriter, r *http.Request) bool {
	tenant := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.NotFound("Run").WriteJSON(w)
		return false
	}
	lookup := h.runLookup
	if lookup == nil {
		lookup = h.service
	}
	run, err := lookup.GetRun(r.Context(), tenant, chi.URLParam(r, "id"))
	if err != nil {
		h.handleServiceError(w, err)
		return false
	}
	if !h.runVisible(r.Context(), tenantID, run) {
		apierror.NotFound("Run").WriteJSON(w)
		return false
	}
	return true
}

// listHidesFindingRuns reports whether the runs list leaves out runs about a
// finding for this caller: without findings:read, or with a restricted data
// scope (each such run would need its own finding check; the caller opens
// them from the finding instead).
func (h *ScanWorkflowHandler) listHidesFindingRuns(ctx context.Context, tenantID shared.ID) bool {
	if !middleware.HasPermission(ctx, "findings:read") {
		return true
	}
	if h.findingScope == nil {
		return false
	}
	scope, err := h.findingScope.Resolve(ctx, tenantID)
	return err != nil || scope != nil
}

// isFindingRun reports whether runs of kind are about a finding (and so
// follow the finding's access rules).
func isFindingRun(kind scanrundom.RunKind) bool {
	return kind == scanrundom.RunKindRetest || kind == scanrundom.RunKindValidation
}

func subjectID(subject map[string]any, key string) (shared.ID, bool) {
	raw, ok := subject[key].(string)
	if !ok {
		return shared.ID{}, false
	}
	id, err := shared.IDFromString(raw)
	return id, err == nil
}
