package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// CompensatingControlHandler handles compensating control CRUD endpoints.
// Uses direct SQL queries for pragmatic speed (no DDD repo layer yet).
type CompensatingControlHandler struct {
	db     *sql.DB
	logger *logger.Logger
	// B2: optional. When set, mutations enqueue a
	// reclassify sweep for the assets this control protects so
	// priority reflects changed protection promptly. Nil = legacy
	// no-fan-out behaviour.
	publisher *controller.ControlChangePublisher
}

// NewCompensatingControlHandler creates a new handler.
func NewCompensatingControlHandler(db *sql.DB, log *logger.Logger) *CompensatingControlHandler {
	return &CompensatingControlHandler{db: db, logger: log}
}

// SetChangePublisher wires the reclassify publisher. Safe after
// construction; nil disables the fan-out.
func (h *CompensatingControlHandler) SetChangePublisher(p *controller.ControlChangePublisher) {
	h.publisher = p
}

// enqueueReclassifyForControl loads asset IDs protected by the given
// control and enqueues one sweep request per tenant. All errors are
// logged — control-change fan-out is advisory and must never fail the
// write that triggered it.
func (h *CompensatingControlHandler) enqueueReclassifyForControl(
	ctx context.Context,
	tenantID shared.ID,
	controlID string,
	reason string,
) {
	if h.publisher == nil {
		return
	}
	rows, err := h.db.QueryContext(ctx,
		`SELECT asset_id FROM compensating_control_assets WHERE control_id = $1`,
		controlID,
	)
	if err != nil {
		h.logger.Warn("load control assets for reclassify failed",
			"control_id", controlID, "error", err)
		return
	}
	defer func() { _ = rows.Close() }()

	assetIDs := make([]shared.ID, 0, 8)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		assetIDs = append(assetIDs, id)
	}
	if len(assetIDs) == 0 {
		return
	}
	h.publisher.PublishChange(ctx, tenantID, assetIDs, reason)
}

// enqueueReclassifyForAssets enqueues a sweep for an explicit asset
// list (used by LinkAssets where we already know the IDs).
func (h *CompensatingControlHandler) enqueueReclassifyForAssets(
	ctx context.Context,
	tenantID shared.ID,
	assetIDRaw []string,
	reason string,
) {
	if h.publisher == nil {
		return
	}
	assetIDs := make([]shared.ID, 0, len(assetIDRaw))
	for _, raw := range assetIDRaw {
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		assetIDs = append(assetIDs, id)
	}
	if len(assetIDs) == 0 {
		return
	}
	h.publisher.PublishChange(ctx, tenantID, assetIDs, reason)
}

// List lists compensating controls for the tenant.
func (h *CompensatingControlHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage)
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

	// B2: protection may have changed (status/reduction_factor) → sweep.
	if tid, ok := middleware.GetTenantIDFromContext(r.Context()); ok {
		h.enqueueReclassifyForControl(r.Context(), tid, id, "control_updated")
	}

	writeJSON(w, http.StatusOK, c)
}

// Delete deletes a compensating control.
func (h *CompensatingControlHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// B2: capture the protected asset set BEFORE the cascade delete
	// drops the link rows. Without this we'd have nothing to sweep.
	protectedAssetIDs := h.loadControlAssetIDs(r.Context(), id)

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

	// Protection removed → findings may reclassify upwards.
	if len(protectedAssetIDs) > 0 && h.publisher != nil {
		if tid, ok := middleware.GetTenantIDFromContext(r.Context()); ok {
			h.publisher.PublishChange(r.Context(), tid, protectedAssetIDs, "control_deleted")
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// loadControlAssetIDs reads the current asset link set for a control.
// Errors are logged and treated as empty — sweep is advisory.
func (h *CompensatingControlHandler) loadControlAssetIDs(ctx context.Context, controlID string) []shared.ID {
	rows, err := h.db.QueryContext(ctx,
		`SELECT asset_id FROM compensating_control_assets WHERE control_id = $1`,
		controlID,
	)
	if err != nil {
		h.logger.Warn("load control assets failed", "control_id", controlID, "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	ids := make([]shared.ID, 0, 8)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids
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

	// B2: test result changed the effective protection → sweep.
	if tid, ok := middleware.GetTenantIDFromContext(r.Context()); ok {
		h.enqueueReclassifyForControl(r.Context(), tid, id, "control_tested")
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

	// Link only assets that belong to the same tenant
	for _, assetID := range req.AssetIDs {
		_, err := h.db.ExecContext(r.Context(),
			`INSERT INTO compensating_control_assets (control_id, asset_id)
			 SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM assets WHERE id = $2 AND tenant_id = $3)
			 ON CONFLICT DO NOTHING`,
			id, assetID, tenantID,
		)
		if err != nil {
			h.logger.Error("compensating control link asset", "error", err, "asset_id", assetID)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
	}

	// B2: new assets came under protection → sweep them so findings
	// on those assets may reclassify down.
	if tid, ok := middleware.GetTenantIDFromContext(r.Context()); ok {
		h.enqueueReclassifyForAssets(r.Context(), tid, req.AssetIDs, "control_linked")
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

	// Link only findings that belong to the same tenant
	for _, findingID := range req.FindingIDs {
		_, err := h.db.ExecContext(r.Context(),
			`INSERT INTO compensating_control_findings (control_id, finding_id)
			 SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM findings WHERE id = $2 AND tenant_id = $3)
			 ON CONFLICT DO NOTHING`,
			id, findingID, tenantID,
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
