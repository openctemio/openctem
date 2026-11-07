package handler

// Replace a scope entry's pattern (docs/architecture/scope-entry-replace.md).

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// ReplaceScopeTargetRequest is the new pattern of an entry and why.
type ReplaceScopeTargetRequest struct {
	Pattern string `json:"pattern" validate:"required,max=500"`
	Reason  string `json:"reason" validate:"required,max=1000"`
}

// ScopeCoverageChangeResponse is what the new pattern adds and removes.
type ScopeCoverageChangeResponse struct {
	// Widens: the new pattern may cover something the old one did not
	// (true when the two cannot be compared). Narrows: the old pattern
	// covered something the new one does not.
	Widens  bool     `json:"widens"`
	Narrows bool     `json:"narrows"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	// AddedAddresses and RemovedAddresses count addresses (set only for
	// address types, Addresses true).
	Addresses        bool   `json:"addresses"`
	AddedAddresses   uint64 `json:"added_addresses"`
	RemovedAddresses uint64 `json:"removed_addresses"`
}

// ScopeZoneUseResponse is a scan zone that names the old entry's addresses.
// Suggested are its ranges with them swapped for the new entry's; the zone
// is changed only through PATCH /scan-zones/{id} (sensors:zones:write).
type ScopeZoneUseResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Ranges    []string `json:"ranges"`
	Suggested []string `json:"suggested"`
}

// ScopeReplaceResponse is a pattern replacement, done or previewed.
type ScopeReplaceResponse struct {
	Old ScopeTargetResponse `json:"old"`
	// New is the replacement (in a preview: what would be created; its id
	// is not saved).
	New ScopeTargetResponse `json:"new"`
	// OldRetired: the old entry is superseded. False while the replacement
	// waits for approval: the old entry stays in effect until then.
	OldRetired     bool                        `json:"old_retired"`
	StepUpRequired bool                        `json:"step_up_required"`
	Change         ScopeCoverageChangeResponse `json:"change"`
	// Zones lists the scan zones that name the old range (callers with
	// sensors:zones:read); ZonesHidden counts them for a caller without it.
	Zones       []ScopeZoneUseResponse `json:"zones"`
	ZonesHidden int                    `json:"zones_hidden"`
}

func (h *ScopeHandler) replaceInput(w http.ResponseWriter, r *http.Request) (scope.ReplaceTargetInput, bool) {
	var req ReplaceScopeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return scope.ReplaceTargetInput{}, false
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return scope.ReplaceTargetInput{}, false
	}
	return scope.ReplaceTargetInput{
		TenantID: middleware.MustGetTenantID(r.Context()), TargetID: chi.URLParam(r, "id"),
		Pattern: req.Pattern, Reason: req.Reason, Actor: scopeActor(r),
	}, true
}

func replaceOut(r *http.Request, res *scope.ReplaceResult) ScopeReplaceResponse {
	out := ScopeReplaceResponse{
		Old: toScopeTargetResponse(res.Old), New: toScopeTargetResponse(res.New),
		OldRetired: res.OldRetired, StepUpRequired: res.StepUpRequired,
		Change: ScopeCoverageChangeResponse{
			Widens: res.Change.Widens, Narrows: res.Change.Narrows,
			Added: nonNil(res.Change.Added), Removed: nonNil(res.Change.Removed),
			Addresses: res.Change.Addresses, AddedAddresses: res.Change.AddedAddresses, RemovedAddresses: res.Change.RemovedAddresses,
		},
		Zones: []ScopeZoneUseResponse{},
	}
	// Zone names and ranges are scan zone data: shown to callers who may
	// read scan zones, counted for everyone else.
	if !middleware.HasPermission(r.Context(), permission.ScanZonesRead.String()) {
		out.ZonesHidden = len(res.Zones)
		return out
	}
	for _, z := range res.Zones {
		out.Zones = append(out.Zones, ScopeZoneUseResponse{ID: z.ID, Name: z.Name, Ranges: nonNil(z.Ranges), Suggested: nonNil(z.Suggested)})
	}
	return out
}

// PreviewReplaceTarget handles POST /api/v1/scope/targets/{id}/replace/preview
// @Summary      Preview a scope entry pattern replacement
// @Description  What replacing the entry's pattern would do: the coverage added and removed, whether the replacement takes effect at once or waits for approval, and the scan zones that name the old range. Runs every check of a new entry; saves nothing and asks no step-up. A refusal is the one the replacement would get.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                     true  "Target ID"
// @Param        body  body      ReplaceScopeTargetRequest  true  "New pattern and reason"
// @Success      200   {object}  ScopeReplaceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/replace/preview [post]
func (h *ScopeHandler) PreviewReplaceTarget(w http.ResponseWriter, r *http.Request) {
	in, ok := h.replaceInput(w, r)
	if !ok {
		return
	}
	res, err := h.service.PreviewReplaceTarget(r.Context(), in)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(replaceOut(r, res))
}

// ReplaceTarget handles POST /api/v1/scope/targets/{id}/replace
// @Summary      Replace a scope entry's pattern
// @Description  Creates a new entry of the same type with the new pattern, through every check and approval rule of a new entry (step-up: 403 STEP_UP_REQUIRED), linked to the old one. In effect at once, the old entry is superseded in the same transaction; waiting for approval, the old entry stays in effect until the replacement is approved. Only an entry in effect can be replaced. Scan zones that name the old range are listed, never changed.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                     true  "Target ID"
// @Param        body  body      ReplaceScopeTargetRequest  true  "New pattern and reason"
// @Success      201   {object}  ScopeReplaceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/replace [post]
func (h *ScopeHandler) ReplaceTarget(w http.ResponseWriter, r *http.Request) {
	in, ok := h.replaceInput(w, r)
	if !ok {
		return
	}
	res, err := h.service.ReplaceTarget(r.Context(), in)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditReplace(r, res, in.Reason)
	h.startWaits(in.TenantID, res.New)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(replaceOut(r, res))
}

// auditReplace records the replacement as one event on the old entry: both
// patterns, both ids, the reason, and whether the old entry was retired now
// or stays in effect until the replacement is approved.
func (h *ScopeHandler) auditReplace(r *http.Request, res *scope.ReplaceResult, reason string) {
	changes := audit.NewChanges()
	changes.Before = auditSnapshot(toScopeTargetResponse(res.Old))
	changes.After = auditSnapshot(toScopeTargetResponse(res.New))
	event := auditsvc.NewSuccessEvent(audit.ActionScopeTargetReplaced, audit.ResourceTypeScopeTarget, res.Old.ID().String()).
		WithResourceName(res.Old.Pattern()).
		WithMessage("Scope entry pattern replaced").
		WithMetadata("old_pattern", res.Old.Pattern()).
		WithMetadata("new_pattern", res.New.Pattern()).
		WithMetadata("old_id", res.Old.ID().String()).
		WithMetadata("new_id", res.New.ID().String()).
		WithMetadata("reason", reason).
		WithMetadata("new_status", res.New.Status().String()).
		WithMetadata("old_retired", res.OldRetired).
		WithMetadata("widens", res.Change.Widens).
		WithChanges(changes)
	logRequestChange(h.audit, h.logger, r, event)
}
