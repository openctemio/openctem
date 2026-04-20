package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// maxIOCRequestBody caps the JSON body size on IOC Create. Prevents a
// malicious client from exhausting memory with a giant body before
// json.Decode fails.
const maxIOCRequestBody = 64 * 1024 // 64 KB — an IOC is tiny

// FindingTenantChecker is the narrow surface IOCHandler needs to verify
// that a user-supplied source_finding_id actually belongs to the
// caller's tenant. *postgres.FindingRepository satisfies this; a nil
// checker skips the check (tests only).
type FindingTenantChecker interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// IOCHandler exposes CRUD for the tenant's indicator-of-compromise
// catalogue. The read/write permissions are reused from threat_intel
// because an IOC is, semantically, a piece of threat intel the
// tenant wants correlated against runtime telemetry.
type IOCHandler struct {
	repo     ioc.Repository
	findings FindingTenantChecker // optional — skip cross-tenant verify in unit tests
	logger   *logger.Logger
}

// NewIOCHandler wires the repo.
func NewIOCHandler(repo ioc.Repository, log *logger.Logger) *IOCHandler {
	return &IOCHandler{
		repo:   repo,
		logger: log.With("handler", "ioc"),
	}
}

// SetFindingChecker wires the tenant-scoped finding lookup that
// validates source_finding_id on Create. Callers SHOULD set this
// outside of unit tests — without it, a client can submit a
// source_finding_id pointing at another tenant's finding, and the
// B6 correlator would then reopen that other tenant's finding on
// the attacker's runtime event (cross-tenant write).
func (h *IOCHandler) SetFindingChecker(c FindingTenantChecker) {
	h.findings = c
}

// iocCreateRequest is the wire format for POST /iocs.
type iocCreateRequest struct {
	Type            string `json:"type"`
	Value           string `json:"value"`
	Source          string `json:"source,omitempty"`            // scan_finding | threat_feed | manual (default manual)
	SourceFindingID string `json:"source_finding_id,omitempty"` // optional — links reopen target
	Confidence      *int   `json:"confidence,omitempty"`        // 0-100, default 75
}

// iocResponse is what we emit back to clients.
type iocResponse struct {
	ID              string  `json:"id"`
	TenantID        string  `json:"tenant_id"`
	Type            string  `json:"type"`
	Value           string  `json:"value"`
	Normalized      string  `json:"normalized"`
	Source          string  `json:"source,omitempty"`
	SourceFindingID *string `json:"source_finding_id,omitempty"`
	Active          bool    `json:"active"`
	Confidence      int     `json:"confidence"`
	FirstSeenAt     string  `json:"first_seen_at"`
	LastSeenAt      string  `json:"last_seen_at"`
}

// Create handles POST /iocs.
func (h *IOCHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(w, r)
	if !ok {
		return
	}

	// Cap body size before Decode so a malicious client can't OOM the
	// process with a giant body. MaxBytesReader returns an error on
	// Decode once the limit is hit.
	r.Body = http.MaxBytesReader(w, r.Body, maxIOCRequestBody)
	var req iocCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid JSON body").WriteJSON(w)
		return
	}

	source := ioc.Source(req.Source)
	if source == "" {
		source = ioc.SourceManual
	}
	ind, err := ioc.NewIndicator(tenantID, ioc.Type(req.Type), req.Value, source)
	if err != nil {
		switch {
		case errors.Is(err, ioc.ErrInvalidType):
			apierror.BadRequest("invalid ioc type").WriteJSON(w)
		case errors.Is(err, ioc.ErrEmptyValue):
			apierror.BadRequest("value is required").WriteJSON(w)
		default:
			apierror.BadRequest(err.Error()).WriteJSON(w)
		}
		return
	}
	if req.Confidence != nil {
		if *req.Confidence < 0 || *req.Confidence > 100 {
			apierror.BadRequest("confidence must be between 0 and 100").WriteJSON(w)
			return
		}
		ind.Confidence = *req.Confidence
	}
	if req.SourceFindingID != "" {
		fid, err := shared.IDFromString(req.SourceFindingID)
		if err != nil {
			apierror.BadRequest("invalid source_finding_id").WriteJSON(w)
			return
		}
		// Cross-tenant guard. Without this a client from tenant A could
		// submit an IOC pointing at a finding in tenant B; the B6
		// correlator would then reopen tenant B's finding when tenant A
		// reported a matching runtime event. Must verify the finding
		// actually belongs to the caller.
		if h.findings != nil {
			if _, err := h.findings.GetByID(r.Context(), tenantID, fid); err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					apierror.NotFound("source_finding_id not found in this tenant").WriteJSON(w)
					return
				}
				h.logger.Error("ioc create: verify source finding failed",
					"tenant_id", tenantID.String(),
					"finding_id", fid.String(),
					"error", err,
				)
				apierror.InternalServerError("failed to verify source_finding_id").WriteJSON(w)
				return
			}
		}
		ind.SourceFindingID = &fid
	}

	if err := h.repo.Create(r.Context(), ind); err != nil {
		h.logger.Error("create ioc failed",
			"tenant_id", tenantID.String(),
			"error", err,
		)
		apierror.InternalServerError("failed to create indicator").WriteJSON(w)
		return
	}

	writeIOCResponse(w, http.StatusCreated, ind)
}

// List handles GET /iocs.
func (h *IOCHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(w, r)
	if !ok {
		return
	}

	// Pagination — bounded defaults, hard cap in repo.
	limit := parsePositiveInt(r.URL.Query().Get("limit"), 50, 200)
	offset := parseNonNegativeInt(r.URL.Query().Get("offset"), 0)

	items, err := h.repo.ListByTenant(r.Context(), tenantID, limit, offset)
	if err != nil {
		h.logger.Error("list iocs failed",
			"tenant_id", tenantID.String(),
			"error", err,
		)
		apierror.InternalServerError("failed to list indicators").WriteJSON(w)
		return
	}

	out := make([]iocResponse, 0, len(items))
	for _, ind := range items {
		out = append(out, toIOCResponse(ind))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items":  out,
		"limit":  limit,
		"offset": offset,
	})
}

// Get handles GET /iocs/{id}.
func (h *IOCHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid id").WriteJSON(w)
		return
	}

	ind, err := h.repo.GetByID(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("indicator not found").WriteJSON(w)
			return
		}
		h.logger.Error("get ioc failed",
			"tenant_id", tenantID.String(),
			"id", id.String(),
			"error", err,
		)
		apierror.InternalServerError("failed to load indicator").WriteJSON(w)
		return
	}
	writeIOCResponse(w, http.StatusOK, ind)
}

// Delete handles DELETE /iocs/{id}. Soft-deactivates the indicator —
// match history in ioc_matches is preserved for the audit trail.
func (h *IOCHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantFromContext(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid id").WriteJSON(w)
		return
	}
	if err := h.repo.Deactivate(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("indicator not found").WriteJSON(w)
			return
		}
		h.logger.Error("deactivate ioc failed",
			"tenant_id", tenantID.String(),
			"id", id.String(),
			"error", err,
		)
		apierror.InternalServerError("failed to deactivate indicator").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tenantFromContext resolves the tenant from the authenticated JWT.
// Writes 401 + returns ok=false when missing so callers can early-
// return with `if !ok { return }`.
func tenantFromContext(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid := middleware.GetTenantID(r.Context())
	if tid == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return shared.ID{}, false
	}
	id, err := shared.IDFromString(tid)
	if err != nil {
		apierror.BadRequest("invalid tenant context").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// parsePositiveInt parses a query-string integer with a default +
// upper cap. Invalid input returns the default.
func parsePositiveInt(s string, def, maxCap int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > maxCap {
		return maxCap
	}
	return n
}

// parseNonNegativeInt parses a query-string integer ≥ 0. Invalid or
// negative returns the default.
func parseNonNegativeInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func writeIOCResponse(w http.ResponseWriter, status int, ind *ioc.Indicator) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(toIOCResponse(ind))
}

func toIOCResponse(ind *ioc.Indicator) iocResponse {
	resp := iocResponse{
		ID:          ind.ID.String(),
		TenantID:    ind.TenantID.String(),
		Type:        string(ind.Type),
		Value:       ind.Value,
		Normalized:  ind.Normalized,
		Source:      string(ind.Source),
		Active:      ind.Active,
		Confidence:  ind.Confidence,
		FirstSeenAt: ind.FirstSeenAt.Format(timeRFC3339),
		LastSeenAt:  ind.LastSeenAt.Format(timeRFC3339),
	}
	if ind.SourceFindingID != nil {
		s := ind.SourceFindingID.String()
		resp.SourceFindingID = &s
	}
	return resp
}

// timeRFC3339 is the ISO-8601 subset our API emits everywhere.
const timeRFC3339 = "2006-01-02T15:04:05Z07:00"
