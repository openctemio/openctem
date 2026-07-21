package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/app"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
)

// SetAuditService wires the audit logger for finding-evidence / remediation
// step mutations. Safe after construction; nil disables audit logging.
func (h *VulnerabilityHandler) SetAuditService(svc *auditapp.AuditService) {
	h.auditService = svc
}

// buildAuditContext extracts audit context from the authenticated request.
func (h *VulnerabilityHandler) buildAuditContext(r *http.Request) auditapp.AuditContext {
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		clientIP = xri
	}
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetUsername(r.Context()),
		ActorIP:    clientIP,
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// AddEvidenceRequest is the body for POST /findings/{id}/evidence.
type AddEvidenceRequest struct {
	Description string `json:"description"`
	Type        string `json:"type"`
	URL         string `json:"url"`
}

// AddFindingEvidence handles POST /api/v1/findings/{id}/evidence.
//
// Attaches a note-type evidence record ({description, type?, url?}) to a
// generic (non-pentest) finding. Loads the finding tenant-scoped — a finding
// outside the caller's tenant returns 404. This is a parallel, tenant-scoped
// path that does NOT invoke the pentest campaign-membership gate used by
// /api/v1/attachments.
func (h *VulnerabilityHandler) AddFindingEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	var req AddEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	evidence, err := h.service.AddFindingEvidence(r.Context(), app.AddEvidenceInput{
		FindingID:   id,
		TenantID:    tenantID,
		UserID:      middleware.GetUserID(r.Context()),
		Description: req.Description,
		Type:        req.Type,
		URL:         req.URL,
	})
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	if h.auditService != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionFindingEvidenceAdded, auditdom.ResourceTypeFinding, id).
			WithResourceName(id).
			WithMessage("Evidence added to finding").
			WithMetadata("evidence_id", evidence.ID).
			WithMetadata("kind", evidence.Kind).
			WithSeverity(auditdom.SeverityLow)
		_ = h.auditService.LogEvent(r.Context(), h.buildAuditContext(r), event)
	}

	writeJSON(w, http.StatusCreated, evidence)
}

// ListFindingEvidence handles GET /api/v1/findings/{id}/evidence.
// Returns evidence only for findings within the caller's tenant.
func (h *VulnerabilityHandler) ListFindingEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	items, err := h.service.ListFindingEvidence(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"data": items, "total": len(items)})
}

// AddRemediationStepRequest is the body for POST /findings/{id}/remediation/steps.
type AddRemediationStepRequest struct {
	Step string `json:"step"`
}

// AddRemediationStep handles POST /api/v1/findings/{id}/remediation/steps.
//
// Appends a single step to the finding's remediation step list, preserving any
// existing steps. Loads the finding tenant-scoped — a finding outside the
// caller's tenant returns 404.
func (h *VulnerabilityHandler) AddRemediationStep(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	var req AddRemediationStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	steps, err := h.service.AddRemediationStep(r.Context(), id, tenantID, req.Step)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	if h.auditService != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionFindingRemediationStepAdded, auditdom.ResourceTypeFinding, id).
			WithResourceName(id).
			WithMessage("Remediation step added to finding").
			WithMetadata("step_count", len(steps)).
			WithSeverity(auditdom.SeverityLow)
		_ = h.auditService.LogEvent(r.Context(), h.buildAuditContext(r), event)
	}

	// MVP model is a plain []string with no per-step status — the note tells the
	// UI to render steps as a plain ordered list.
	writeJSON(w, http.StatusOK, map[string]any{
		"steps": steps,
		"total": len(steps),
		"note":  "steps are plain strings; no per-step status tracking",
	})
}
