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
	"github.com/openctemio/api/pkg/pagination"
)

// CompensatingControlHandler handles compensating control CRUD endpoints.
// Uses direct SQL queries for pragmatic speed (no DDD repo layer yet).
type CompensatingControlHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewCompensatingControlHandler creates a new handler.
func NewCompensatingControlHandler(db *sql.DB, log *logger.Logger) *CompensatingControlHandler {
	return &CompensatingControlHandler{db: db, logger: log}
}

// List lists compensating controls for the tenant.
func (h *CompensatingControlHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	// Count total
	var total int64
	err := h.db.QueryRowContext(r.Context(),
		"SELECT COUNT(*) FROM compensating_controls WHERE tenant_id = $1", tenantID,
	).Scan(&total)
	if err != nil {
		h.logger.Error("compensating control list count", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, name, description, control_type, status, reduction_factor,
		        last_tested_at, test_result, test_evidence, expires_at,
		        created_by, created_at, updated_at
		   FROM compensating_controls
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC
		  LIMIT $2 OFFSET $3`,
		tenantID, page.Limit(), page.Offset(),
	)
	if err != nil {
		h.logger.Error("compensating control list", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer rows.Close() //nolint:errcheck

	items := make([]CompensatingControlResponse, 0, perPage)
	for rows.Next() {
		var c CompensatingControlResponse
		var desc, testResult, testEvidence, createdBy sql.NullString
		var reductionFactor sql.NullFloat64
		var lastTestedAt, expiresAt sql.NullTime
		if err := rows.Scan(
			&c.ID, &c.Name, &desc, &c.ControlType, &c.Status, &reductionFactor,
			&lastTestedAt, &testResult, &testEvidence, &expiresAt,
			&createdBy, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			h.logger.Error("compensating control scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		c.Description = desc.String
		c.ReductionFactor = reductionFactor.Float64
		c.TestResult = testResult.String
		c.TestEvidence = testEvidence.String
		c.CreatedBy = createdBy.String
		if lastTestedAt.Valid {
			c.LastTestedAt = &lastTestedAt.Time
		}
		if expiresAt.Valid {
			c.ExpiresAt = &expiresAt.Time
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("compensating control rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(items, total, page))
}

// Get retrieves a single compensating control.
func (h *CompensatingControlHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var c CompensatingControlResponse
	var desc, testResult, testEvidence, createdBy sql.NullString
	var reductionFactor sql.NullFloat64
	var lastTestedAt, expiresAt sql.NullTime

	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, name, description, control_type, status, reduction_factor,
		        last_tested_at, test_result, test_evidence, expires_at,
		        created_by, created_at, updated_at
		   FROM compensating_controls
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id,
	).Scan(
		&c.ID, &c.Name, &desc, &c.ControlType, &c.Status, &reductionFactor,
		&lastTestedAt, &testResult, &testEvidence, &expiresAt,
		&createdBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint // direct comparison ok for sql.ErrNoRows
			apierror.NotFound("compensating control not found").WriteJSON(w)
			return
		}
		h.logger.Error("compensating control get", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	c.Description = desc.String
	c.ReductionFactor = reductionFactor.Float64
	c.TestResult = testResult.String
	c.TestEvidence = testEvidence.String
	c.CreatedBy = createdBy.String
	if lastTestedAt.Valid {
		c.LastTestedAt = &lastTestedAt.Time
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}

	writeJSON(w, http.StatusOK, c)
}

// Create creates a new compensating control.
func (h *CompensatingControlHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateCompensatingControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}

	var c CompensatingControlResponse
	err := h.db.QueryRowContext(r.Context(),
		`INSERT INTO compensating_controls
		        (tenant_id, name, description, control_type, status, reduction_factor, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, COALESCE(NULLIF($5,''), 'active'), $6, $7, $8)
		 RETURNING id, name, description, control_type, status, reduction_factor,
		           last_tested_at, test_result, test_evidence, expires_at,
		           created_by, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.ControlType, req.Status,
		req.ReductionFactor, nilTime(req.ExpiresAt), nilString(userID),
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ControlType, &c.Status, &c.ReductionFactor,
		&c.LastTestedAt, &c.TestResult, &c.TestEvidence, &c.ExpiresAt,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		h.logger.Error("compensating control create", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, c)
}

// Update updates an existing compensating control.
func (h *CompensatingControlHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req CreateCompensatingControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	var c CompensatingControlResponse
	err := h.db.QueryRowContext(r.Context(),
		`UPDATE compensating_controls
		    SET name = $3, description = $4, control_type = $5,
		        status = COALESCE(NULLIF($6,''), status),
		        reduction_factor = $7, expires_at = $8, updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2
		 RETURNING id, name, description, control_type, status, reduction_factor,
		           last_tested_at, test_result, test_evidence, expires_at,
		           created_by, created_at, updated_at`,
		tenantID, id, req.Name, req.Description, req.ControlType,
		req.Status, req.ReductionFactor, nilTime(req.ExpiresAt),
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ControlType, &c.Status, &c.ReductionFactor,
		&c.LastTestedAt, &c.TestResult, &c.TestEvidence, &c.ExpiresAt,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.NotFound("compensating control not found").WriteJSON(w)
			return
		}
		h.logger.Error("compensating control update", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// Delete deletes a compensating control.
func (h *CompensatingControlHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	res, err := h.db.ExecContext(r.Context(),
		"DELETE FROM compensating_controls WHERE tenant_id = $1 AND id = $2",
		tenantID, id,
	)
	if err != nil {
		h.logger.Error("compensating control delete", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		apierror.NotFound("compensating control not found").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RecordTest records a test result for a compensating control.
func (h *CompensatingControlHandler) RecordTest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		TestResult   string `json:"test_result"`
		TestEvidence string `json:"test_evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	var c CompensatingControlResponse
	err := h.db.QueryRowContext(r.Context(),
		`UPDATE compensating_controls
		    SET test_result = $3, test_evidence = $4, last_tested_at = NOW(), updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2
		 RETURNING id, name, description, control_type, status, reduction_factor,
		           last_tested_at, test_result, test_evidence, expires_at,
		           created_by, created_at, updated_at`,
		tenantID, id, req.TestResult, req.TestEvidence,
	).Scan(
		&c.ID, &c.Name, &c.Description, &c.ControlType, &c.Status, &c.ReductionFactor,
		&c.LastTestedAt, &c.TestResult, &c.TestEvidence, &c.ExpiresAt,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.NotFound("compensating control not found").WriteJSON(w)
			return
		}
		h.logger.Error("compensating control record test", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// LinkAssets links assets to a compensating control.
func (h *CompensatingControlHandler) LinkAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		AssetIDs []string `json:"asset_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Verify control belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM compensating_controls WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("compensating control not found").WriteJSON(w)
		return
	}

	for _, assetID := range req.AssetIDs {
		_, err := h.db.ExecContext(r.Context(),
			`INSERT INTO compensating_control_assets (control_id, asset_id)
			 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			id, assetID,
		)
		if err != nil {
			h.logger.Error("compensating control link asset", "error", err, "asset_id", assetID)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// LinkFindings links findings to a compensating control.
func (h *CompensatingControlHandler) LinkFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		FindingIDs []string `json:"finding_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Verify control belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM compensating_controls WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("compensating control not found").WriteJSON(w)
		return
	}

	for _, findingID := range req.FindingIDs {
		_, err := h.db.ExecContext(r.Context(),
			`INSERT INTO compensating_control_findings (control_id, finding_id)
			 VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			id, findingID,
		)
		if err != nil {
			h.logger.Error("compensating control link finding", "error", err, "finding_id", findingID)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Request/Response Types ───

// CreateCompensatingControlRequest is the request body for creating/updating a compensating control.
type CreateCompensatingControlRequest struct {
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	ControlType     string     `json:"control_type"`
	Status          string     `json:"status"`
	ReductionFactor float64    `json:"reduction_factor"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

// CompensatingControlResponse is the JSON response for a compensating control.
type CompensatingControlResponse struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	ControlType     string     `json:"control_type"`
	Status          string     `json:"status"`
	ReductionFactor float64    `json:"reduction_factor"`
	LastTestedAt    *time.Time `json:"last_tested_at,omitempty"`
	TestResult      string     `json:"test_result,omitempty"`
	TestEvidence    string     `json:"test_evidence,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedBy       string     `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// nilTime returns nil interface if time pointer is nil, otherwise the time value.
func nilTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// nilString returns nil interface if string is empty, otherwise the string.
func nilString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
