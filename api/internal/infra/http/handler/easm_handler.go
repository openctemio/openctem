package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
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
	rules  EASMRuleService
	// suggestions: the attack surface suggestion cards.
	suggestions EASMSuggester
	audit       AttributionAuditor
	changes     EASMChangeLister
	logger      *logger.Logger
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
// @Param        include_discovered  query  bool  false  "Count discovered assets nobody claimed too (default: the attributed inventory only)"
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
	// DecideAs is a person's decision: confirming also adds each confirmed
	// asset's exact scope entry where the organization's setting allows.
	DecideAs(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, actor easmapp.ScopeActor) (*easmapp.DecisionResult, error)
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
	paging, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	q.Limit, q.Offset = paging.Limit(), paging.Offset()
	// Which fixes an address row offers depends on the caller's own
	// permissions (taken from the token, never the request).
	q.Caller = easmapp.ReviewCaller{
		CanApprove: middleware.HasPermission(r.Context(), permission.ScopeApprove.String()),
		CanRequest: middleware.HasPermission(r.Context(), permission.ScopeWrite.String()),
	}
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
	// State: confirmed, rejected, dependency, monitor_only, needs_review,
	// or automatic (forget a person's decision: the asset goes back to what
	// its evidence says; the undo of "Not ours").
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
	res, err := h.review.DecideAs(ctx, tenantID, req.AssetIDs, attribution.State(req.State), confirmActor(ctx))
	if err != nil {
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
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
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
		}
		auditConfirmEntries(ctx, h.audit, actx, res.Scope, "review_queue")
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
			auditapp.RecordOrWarn(ctx, h.logger, h.audit, actx, event)
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

// ReviewCount is how many decisions wait on the attack surface, the number
// the Suggestions tab and the sidebar badge show: one per suggestion card
// (GET /easm/suggestions, rule cards included), not one per queue row
// (research/117). The request context carries the caller, so the data scope
// applies. Without suggestion cards it is the queue's row count. The caller
// checks the route's gates (assets:read, the attack_surface module).
func (h *EASMHandler) ReviewCount(ctx context.Context, tenantID shared.ID) (int, error) {
	if h.suggestions != nil {
		out, err := h.suggestionCards(ctx, tenantID, false)
		if err != nil {
			return 0, err
		}
		return out.Total, nil
	}
	if h.review == nil {
		return 0, errors.New("review queue not configured")
	}
	page, err := h.review.Queue(ctx, tenantID, easmapp.ReviewQuery{Limit: 1})
	if err != nil {
		return 0, err
	}
	return page.Total, nil
}

// EASMChangeLister serves the typed attack-surface changes (RFC-080).
type EASMChangeLister interface {
	List(ctx context.Context, tenantID shared.ID, q easmchange.Query) (*easmchange.Page, error)
}

// SetChanges wires the typed change feed.
func (h *EASMHandler) SetChanges(c EASMChangeLister) *EASMHandler {
	h.changes = c
	return h
}

// HasChanges reports whether the change feed is wired.
func (h *EASMHandler) HasChanges() bool { return h.changes != nil }

// Changes handles GET /api/v1/easm/changes
// @Summary      What changed on the attack surface
// @Description  Typed changes of the external attack surface in a window (default the last 7 days, at most 31): new and removed hosts, opened and closed ports, new and expiring certificates, DNS changes and dangling records, technology changes and new exposures. Read from asset state history, the asset change timeline and exposure events; narrowed to the caller's data scope. counts covers every kind in the window.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        from    query  string  false  "Window start (RFC 3339)"
// @Param        to      query  string  false  "Window end (RFC 3339), default now"
// @Param        kind    query  string  false  "Comma-separated kinds"
// @Param        limit   query  int     false  "Page size (max 200)"
// @Param        cursor  query  string  false  "Next page cursor"
// @Success      200  {object}  easmchange.Page
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Param        include_discovered  query  bool  false  "Count discovered assets nobody claimed too (default: the attributed inventory only)"
// @Router       /easm/changes [get]
func (h *EASMHandler) Changes(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	v := r.URL.Query()
	var q easmchange.Query
	for name, dst := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if s := v.Get(name); s != "" {
			t, perr := time.Parse(time.RFC3339, s)
			if perr != nil {
				apierror.BadRequest(name + " must be an RFC 3339 time").WriteJSON(w)
				return
			}
			*dst = t.UTC()
		}
	}
	if s := v.Get("kind"); s != "" {
		kinds, kerr := easmchange.ParseKinds(strings.Split(s, ","))
		if kerr != nil {
			apierror.BadRequest(kerr.Error()).WriteJSON(w)
			return
		}
		q.Kinds = kinds
	}
	limit, ok := listLimit(w, r, 50, easmchange.MaxPageSize)
	if !ok {
		return
	}
	q.Limit = limit
	q.Cursor = v.Get("cursor")
	page, err := h.changes.List(r.Context(), tenantID, q)
	if err != nil {
		if errors.Is(err, easmchange.ErrInvalidQuery) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("failed to list attack surface changes", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list changes").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}
