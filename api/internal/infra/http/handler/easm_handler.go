package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMSummarizer builds the EASM overview.
type EASMSummarizer interface {
	Summary(ctx context.Context, tenantID shared.ID) (*easmapp.Summary, error)
}

// EASMHandler serves the EASM overview (RFC-036 §6.10).
type EASMHandler struct {
	svc    EASMSummarizer
	review EASMReviewer
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewEASMHandler creates the handler.
func NewEASMHandler(svc EASMSummarizer, log *logger.Logger) *EASMHandler {
	return &EASMHandler{svc: svc, logger: log}
}

// Summary handles GET /api/v1/easm/summary
// @Summary      EASM overview
// @Description  The external attack surface in one call: surface assets by type and internet-facing services, attribution (confirmed, awaiting review and the age of the oldest review item, dependency, monitor only, rejected), assets first seen in the last 7/30 days and since the latest CTEM cycle started, open external exposures by severity and type, the top open risks, and how fresh the Certificate-Transparency monitoring is. Narrowed to the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  easmapp.Summary
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/summary [get]
func (h *EASMHandler) Summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	out, err := h.svc.Summary(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to build EASM summary", "error", err)
		apierror.InternalServerError("failed to build EASM summary").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// EASMReviewer serves the attribution review queue (RFC-036 §6.4).
type EASMReviewer interface {
	Queue(ctx context.Context, tenantID shared.ID, q easmapp.ReviewQuery) (*easmapp.ReviewPage, error)
	Decide(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, actorID string) (*easmapp.DecisionResult, error)
}

// SetReview wires the review queue and its audit trail.
func (h *EASMHandler) SetReview(rv EASMReviewer, audit AttributionAuditor) *EASMHandler {
	h.review, h.audit = rv, audit
	return h
}

// Candidates handles GET /api/v1/easm/candidates
// @Summary      EASM review queue
// @Description  Assets the platform found but could not prove are the organization's (attribution needs_review or candidate by default), most confident first, each with its evidence. Narrowed to the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        states          query string false "Attribution states (comma-separated); default needs_review,candidate"
// @Param        types           query string false "Asset types (comma-separated)"
// @Param        min_confidence  query int    false "Minimum confidence 0-100"
// @Param        search          query string false "Substring of the asset name"
// @Param        reason          query string false "Only rows set by this attribution rule (e.g. fqdn_under_asserted_root)"
// @Param        page            query int    false "Page number" default(1)
// @Param        per_page        query int    false "Items per page" default(50) maximum(100)
// @Success      200  {object}  easmapp.ReviewPage
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/candidates [get]
func (h *EASMHandler) Candidates(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	query := r.URL.Query()
	q := easmapp.ReviewQuery{
		Types:         parseQueryArray(query.Get("types")),
		MinConfidence: parseQueryIntBounded(query.Get("min_confidence"), 0, 0, 100),
		Search:        query.Get("search"),
		Reason:        query.Get("reason"),
	}
	if len(q.Search) > 255 {
		apierror.BadRequest("search is too long").WriteJSON(w)
		return
	}
	for _, s := range parseQueryArray(query.Get("states")) {
		st := attribution.State(s)
		if !st.Valid() {
			apierror.BadRequest("unknown attribution state").WriteJSON(w)
			return
		}
		q.States = append(q.States, st)
	}
	page := parseQueryIntBounded(query.Get("page"), 1, 1, 100000)
	q.Limit = parseQueryIntBounded(query.Get("per_page"), 50, 1, MaxPerPage)
	q.Offset = (page - 1) * q.Limit
	out, err := h.review.Queue(r.Context(), tenantID, q)
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("invalid review filter").WriteJSON(w)
			return
		}
		h.logger.Error("failed to list EASM review queue", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list review queue").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// EASMDecisionRequest is one decision on many assets.
type EASMDecisionRequest struct {
	AssetIDs []string `json:"asset_ids"`
	// State: confirmed, rejected, dependency, monitor_only or needs_review.
	State string `json:"state"`
	// Note is an optional reason, kept in the audit log.
	Note string `json:"note,omitempty"`
}

// maxDecisionNote bounds the audit note.
const maxDecisionNote = 500

// Decide handles POST /api/v1/easm/candidates/decisions
// @Summary      Decide EASM attribution in bulk
// @Description  Record whether each asset is the organization's: confirmed lets scans reach it; rejected, dependency and monitor_only keep it passive. At most 200 assets per call. Assets that are not the organization's, are deleted or are outside the caller's data scope are listed in not_found. Each decision is audited.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMDecisionRequest true "Decision"
// @Success      200  {object}  easmapp.DecisionResult
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/candidates/decisions [post]
func (h *EASMHandler) Decide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req EASMDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.Note) > maxDecisionNote {
		apierror.BadRequest("note is too long").WriteJSON(w)
		return
	}
	userID := middleware.GetUserID(ctx)
	res, err := h.review.Decide(ctx, tenantID, req.AssetIDs, attribution.State(req.State), userID)
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
			return
		}
		h.logger.Error("failed to save EASM decisions", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to save decisions").WriteJSON(w)
		return
	}
	if h.audit != nil {
		actx := auditapp.AuditContext{
			TenantID: tenant, ActorID: userID, ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		}
		for _, d := range res.Decided {
			event := auditapp.NewSuccessEvent(auditdom.ActionAssetAttributionDecided, auditdom.ResourceTypeAsset, d.AssetID).
				WithMessage("Attribution set to "+d.To).
				WithMetadata("from", d.From).
				WithMetadata("to", d.To).
				WithMetadata("via", "review_queue").
				WithSeverity(auditdom.SeverityMedium)
			if req.Note != "" {
				event = event.WithMetadata("note", logger.SanitizeValue(req.Note))
			}
			_ = h.audit.LogEvent(ctx, actx, event)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// easmValidationMessage strips the sentinel prefix from a validation error.
func easmValidationMessage(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// HasReview reports whether the review queue is wired.
func (h *EASMHandler) HasReview() bool { return h.review != nil }
