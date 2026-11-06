package handler

// Cross-rule correlation of findings (research/134 section 12): the
// detections of one issue, "possibly related" suggestions, and the actions a
// person takes on them. The path finding is checked against the caller's
// data scope by the route guard; a second finding named in a body is
// checked here, and correlations never leave one asset.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FindingCorrelations is what the correlation endpoints need (the postgres
// finding correlation repository).
type FindingCorrelations interface {
	Detections(ctx context.Context, tenantID, findingID shared.ID) (detections, related []postgres.Detection, err error)
	ReleaseByUser(ctx context.Context, tenantID, memberID, userID shared.ID) (bool, error)
	ConfirmSuggestion(ctx context.Context, tenantID, primaryID, memberID shared.ID) (bool, error)
}

// SetFindingCorrelations wires the correlation endpoints (nil: 404).
func (h *VulnerabilityHandler) SetFindingCorrelations(c FindingCorrelations) { h.correlations = c }

// FindingDetectionsResponse lists the detections of the finding's issue.
type FindingDetectionsResponse struct {
	// Detections: the primary and its correlated duplicates, empty when the
	// finding is not part of a correlation.
	Detections []FindingDetection `json:"detections"`
	// PossiblyRelated: suggestions a person may confirm; nothing changed.
	PossiblyRelated []FindingDetection `json:"possibly_related"`
}

// FindingDetection is one detection.
type FindingDetection struct {
	FindingID  string    `json:"finding_id"`
	RuleID     string    `json:"rule_id"`
	Title      string    `json:"title"`
	MatchedURL string    `json:"matched_url"`
	FirstSeen  time.Time `json:"first_seen"`
	Primary    bool      `json:"primary"`
}

func toDetections(in []postgres.Detection) []FindingDetection {
	out := make([]FindingDetection, 0, len(in))
	for _, d := range in {
		out = append(out, FindingDetection(d))
	}
	return out
}

// GetFindingDetections handles GET /api/v1/findings/{id}/detections.
//
//	@Summary		Detections of the finding's issue
//	@Description	The primary finding of a correlated issue and the detections folded into it (each a correlated duplicate), and "possibly related" findings a person may confirm. Correlations never cross assets.
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	FindingDetectionsResponse
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/detections [get]
func (h *VulnerabilityHandler) GetFindingDetections(w http.ResponseWriter, r *http.Request) {
	id, ok := h.correlationFinding(w, r)
	if !ok {
		return
	}
	tenantID, ok := correlationTenant(w, r)
	if !ok {
		return
	}
	dets, related, err := h.correlations.Detections(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FindingDetectionsResponse{Detections: toDetections(dets), PossiblyRelated: toDetections(related)})
}

// ReleaseFindingCorrelation handles POST /api/v1/findings/{id}/correlation/release.
//
//	@Summary		Un-duplicate a correlated finding
//	@Description	The finding stops being a correlated duplicate: its status from before the correlation is restored, and it is never correlated with that primary automatically again. Audited.
//	@Tags			Findings
//	@Security		BearerAuth
//	@Param			id	path	string	true	"ID of the correlated duplicate"
//	@Success		204
//	@Failure		404	{object}	apierror.Error
//	@Failure		409	{object}	apierror.Error
//	@Router			/findings/{id}/correlation/release [post]
func (h *VulnerabilityHandler) ReleaseFindingCorrelation(w http.ResponseWriter, r *http.Request) {
	id, ok := h.correlationFinding(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tenantID, ok := correlationTenant(w, r)
	if !ok {
		return
	}
	uid, _ := shared.IDFromString(middleware.GetUserID(ctx))
	done, err := h.correlations.ReleaseByUser(ctx, tenantID, id, uid)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	if !done {
		apierror.Conflict("The finding is not a correlated duplicate").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ConfirmFindingCorrelationRequest names the related finding to fold in.
type ConfirmFindingCorrelationRequest struct {
	FindingID string `json:"finding_id" validate:"required,uuid"`
}

// ConfirmFindingCorrelation handles POST /api/v1/findings/{id}/correlation/approve.
//
//	@Summary		Confirm a "possibly related" finding
//	@Description	The finding in the body, suggested as possibly related to the one in the path, becomes its correlated duplicate (reversible with correlation/release). Both must be open, in the caller's data scope and on the same asset. Audited.
//	@Tags			Findings
//	@Accept			json
//	@Security		BearerAuth
//	@Param			id		path	string								true	"ID of the primary finding"
//	@Param			request	body	ConfirmFindingCorrelationRequest	true	"The related finding"
//	@Success		204
//	@Failure		404	{object}	apierror.Error
//	@Failure		409	{object}	apierror.Error
//	@Router			/findings/{id}/correlation/approve [post]
func (h *VulnerabilityHandler) ConfirmFindingCorrelation(w http.ResponseWriter, r *http.Request) {
	id, ok := h.correlationFinding(w, r)
	if !ok {
		return
	}
	var req ConfirmFindingCorrelationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	ctx := r.Context()
	tenantID, ok := correlationTenant(w, r)
	if !ok {
		return
	}
	// The body's finding must be in the caller's scope too (404 otherwise).
	member, err := h.service.GetFindingWithScope(ctx, tenantID.String(), req.FindingID, middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	done, err := h.correlations.ConfirmSuggestion(ctx, tenantID, id, member.ID())
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	if !done {
		apierror.Conflict("No open suggestion relates these findings, or one of them is no longer open").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// correlationFinding resolves the path finding in the caller's tenant and
// data scope; 404 otherwise, or when correlation is not wired.
func (h *VulnerabilityHandler) correlationFinding(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	if h.correlations == nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return shared.ID{}, false
	}
	ctx := r.Context()
	f, err := h.service.GetFindingWithScope(ctx, middleware.MustGetTenantID(ctx), r.PathValue("id"), middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return shared.ID{}, false
	}
	return f.ID(), true
}

// correlationTenant is the authenticated tenant.
func correlationTenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Tenant context required").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}
