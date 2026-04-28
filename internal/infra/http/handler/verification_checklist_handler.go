package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// VerificationChecklistHandler handles finding verification checklist endpoints.
type VerificationChecklistHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewVerificationChecklistHandler creates a new handler.
func NewVerificationChecklistHandler(db *sql.DB, log *logger.Logger) *VerificationChecklistHandler {
	return &VerificationChecklistHandler{db: db, logger: log}
}

type checklistResponse struct {
	ID                  string  `json:"id"`
	FindingID           string  `json:"finding_id"`
	ExposureCleared     bool    `json:"exposure_cleared"`
	EvidenceAttached    bool    `json:"evidence_attached"`
	RegisterUpdated     bool    `json:"register_updated"`
	MonitoringAdded     *bool   `json:"monitoring_added"`
	RegressionScheduled *bool   `json:"regression_scheduled"`
	Notes               string  `json:"notes"`
	IsComplete          bool    `json:"is_complete"`
	CompletedBy         *string `json:"completed_by,omitempty"`
	CompletedAt         *string `json:"completed_at,omitempty"`
}

// Get returns the verification checklist for a finding. Creates one if it doesn't exist.
func (h *VerificationChecklistHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "findingId")

	// Verify finding belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1 AND tenant_id = $2)",
		findingID, tenantID,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("finding not found").WriteJSON(w)
		return
	}

	// Upsert checklist (auto-create if not exists)
	query := `
		INSERT INTO finding_verification_checklists (finding_id, tenant_id)
		VALUES ($1, $2)
		ON CONFLICT (finding_id) DO NOTHING
		RETURNING id
	`
	h.db.ExecContext(r.Context(), query, findingID, tenantID) //nolint:errcheck

	// Fetch
	var resp checklistResponse
	var completedAt sql.NullTime
	var completedBy sql.NullString
	var monitoringAdded, regressionScheduled sql.NullBool

	err := h.db.QueryRowContext(r.Context(), `
		SELECT id, finding_id, exposure_cleared, evidence_attached, register_updated,
			monitoring_added, regression_scheduled, COALESCE(notes, ''),
			completed_by, completed_at
		FROM finding_verification_checklists
		WHERE finding_id = $1 AND tenant_id = $2
	`, findingID, tenantID).Scan(
		&resp.ID, &resp.FindingID, &resp.ExposureCleared, &resp.EvidenceAttached,
		&resp.RegisterUpdated, &monitoringAdded, &regressionScheduled, &resp.Notes,
		&completedBy, &completedAt,
	)
	if err != nil {
		h.logger.Error("get verification checklist", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	if monitoringAdded.Valid {
		resp.MonitoringAdded = &monitoringAdded.Bool
	}
	if regressionScheduled.Valid {
		resp.RegressionScheduled = &regressionScheduled.Bool
	}
	if completedBy.Valid {
		resp.CompletedBy = &completedBy.String
	}
	if completedAt.Valid {
		t := completedAt.Time.Format(time.RFC3339)
		resp.CompletedAt = &t
	}

	// Compute is_complete
	resp.IsComplete = resp.ExposureCleared && resp.EvidenceAttached && resp.RegisterUpdated
	if resp.MonitoringAdded != nil && !*resp.MonitoringAdded {
		resp.IsComplete = false
	}
	if resp.RegressionScheduled != nil && !*resp.RegressionScheduled {
		resp.IsComplete = false
	}

	writeJSON(w, http.StatusOK, resp)
}

// Update updates checklist items.
func (h *VerificationChecklistHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "findingId")

	var req struct {
		ExposureCleared     *bool   `json:"exposure_cleared"`
		EvidenceAttached    *bool   `json:"evidence_attached"`
		RegisterUpdated     *bool   `json:"register_updated"`
		MonitoringAdded     *bool   `json:"monitoring_added"`
		RegressionScheduled *bool   `json:"regression_scheduled"`
		Notes               *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Verify finding belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1 AND tenant_id = $2)",
		findingID, tenantID,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("finding not found").WriteJSON(w)
		return
	}

	// Ensure checklist exists
	h.db.ExecContext(r.Context(), //nolint:errcheck
		"INSERT INTO finding_verification_checklists (finding_id, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		findingID, tenantID)

	// Update fields that were provided
	query := `
		UPDATE finding_verification_checklists SET
			exposure_cleared = COALESCE($3, exposure_cleared),
			evidence_attached = COALESCE($4, evidence_attached),
			register_updated = COALESCE($5, register_updated),
			monitoring_added = COALESCE($6, monitoring_added),
			regression_scheduled = COALESCE($7, regression_scheduled),
			notes = COALESCE($8, notes),
			updated_at = NOW()
		WHERE finding_id = $1 AND tenant_id = $2
	`
	_, err := h.db.ExecContext(r.Context(), query,
		findingID, tenantID,
		req.ExposureCleared, req.EvidenceAttached, req.RegisterUpdated,
		req.MonitoringAdded, req.RegressionScheduled, req.Notes,
	)
	if err != nil {
		h.logger.Error("update verification checklist", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	// Return updated checklist
	h.Get(w, r)
}
