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

// CTEMCycleHandler handles CTEM cycle CRUD and state transition endpoints.
// Uses direct SQL queries for pragmatic speed (no DDD repo layer yet).
type CTEMCycleHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewCTEMCycleHandler creates a new handler.
func NewCTEMCycleHandler(db *sql.DB, log *logger.Logger) *CTEMCycleHandler {
	return &CTEMCycleHandler{db: db, logger: log}
}

// List lists CTEM cycles for the tenant.
func (h *CTEMCycleHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	var total int64
	err := h.db.QueryRowContext(r.Context(),
		"SELECT COUNT(*) FROM ctem_cycles WHERE tenant_id = $1", tenantID,
	).Scan(&total)
	if err != nil {
		h.logger.Error("ctem cycle list count", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, name, status, start_date, end_date, charter,
		        closed_by, closed_at, created_by, created_at, updated_at
		   FROM ctem_cycles
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC
		  LIMIT $2 OFFSET $3`,
		tenantID, page.Limit(), page.Offset(),
	)
	if err != nil {
		h.logger.Error("ctem cycle list", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer rows.Close() //nolint:errcheck

	items := make([]CTEMCycleResponse, 0, perPage)
	for rows.Next() {
		c, err := h.scanCycle(rows)
		if err != nil {
			h.logger.Error("ctem cycle scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ctem cycle rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(items, total, page))
}

// Get retrieves a single CTEM cycle.
func (h *CTEMCycleHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	row := h.db.QueryRowContext(r.Context(),
		`SELECT id, name, status, start_date, end_date, charter,
		        closed_by, closed_at, created_by, created_at, updated_at
		   FROM ctem_cycles
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id,
	)
	c, err := h.scanCycle(row)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.NotFound("cycle not found").WriteJSON(w)
			return
		}
		h.logger.Error("ctem cycle get", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// Create creates a new CTEM cycle.
func (h *CTEMCycleHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateCTEMCycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}

	charterJSON, err := json.Marshal(req.Charter)
	if err != nil {
		apierror.BadRequest("invalid charter JSON").WriteJSON(w)
		return
	}

	var c CTEMCycleResponse
	var startDate, endDate sql.NullString
	var closedBy sql.NullString
	var closedAt sql.NullTime
	var charter []byte

	err = h.db.QueryRowContext(r.Context(),
		`INSERT INTO ctem_cycles
		        (tenant_id, name, start_date, end_date, charter, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, status, start_date, end_date, charter,
		           closed_by, closed_at, created_by, created_at, updated_at`,
		tenantID, req.Name, nilString(req.StartDate), nilString(req.EndDate),
		charterJSON, userID,
	).Scan(
		&c.ID, &c.Name, &c.Status, &startDate, &endDate, &charter,
		&closedBy, &closedAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		h.logger.Error("ctem cycle create", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	c.StartDate = startDate.String
	c.EndDate = endDate.String
	c.ClosedBy = closedBy.String
	if closedAt.Valid {
		c.ClosedAt = &closedAt.Time
	}
	if charter != nil {
		_ = json.Unmarshal(charter, &c.Charter)
	}
	if c.Charter == nil {
		c.Charter = map[string]any{}
	}

	writeJSON(w, http.StatusCreated, c)
}

// Update updates a CTEM cycle (only allowed in planning status).
func (h *CTEMCycleHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req CreateCTEMCycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	charterJSON, err := json.Marshal(req.Charter)
	if err != nil {
		apierror.BadRequest("invalid charter JSON").WriteJSON(w)
		return
	}

	var c CTEMCycleResponse
	var startDate, endDate sql.NullString
	var closedBy sql.NullString
	var closedAt sql.NullTime
	var charter []byte

	err = h.db.QueryRowContext(r.Context(),
		`UPDATE ctem_cycles
		    SET name = $3, start_date = $4, end_date = $5, charter = $6, updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2 AND status = 'planning'
		 RETURNING id, name, status, start_date, end_date, charter,
		           closed_by, closed_at, created_by, created_at, updated_at`,
		tenantID, id, req.Name, nilString(req.StartDate), nilString(req.EndDate), charterJSON,
	).Scan(
		&c.ID, &c.Name, &c.Status, &startDate, &endDate, &charter,
		&closedBy, &closedAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.BadRequest("cycle not found or not in planning status").WriteJSON(w)
			return
		}
		h.logger.Error("ctem cycle update", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	c.StartDate = startDate.String
	c.EndDate = endDate.String
	c.ClosedBy = closedBy.String
	if closedAt.Valid {
		c.ClosedAt = &closedAt.Time
	}
	if charter != nil {
		_ = json.Unmarshal(charter, &c.Charter)
	}
	if c.Charter == nil {
		c.Charter = map[string]any{}
	}

	writeJSON(w, http.StatusOK, c)
}

// Activate transitions a cycle from planning to active.
func (h *CTEMCycleHandler) Activate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	c, err := h.transitionStatus(r, w, tenantID, id, "planning", "active")
	if err != nil {
		return // error already written
	}
	writeJSON(w, http.StatusOK, c)
}

// StartReview transitions a cycle from active to review.
func (h *CTEMCycleHandler) StartReview(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	c, err := h.transitionStatus(r, w, tenantID, id, "active", "review")
	if err != nil {
		return // error already written
	}
	writeJSON(w, http.StatusOK, c)
}

// Close transitions a cycle from review to closed.
func (h *CTEMCycleHandler) Close(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := chi.URLParam(r, "id")

	var c CTEMCycleResponse
	var startDate, endDate sql.NullString
	var closedBy sql.NullString
	var closedAt sql.NullTime
	var charter []byte

	err := h.db.QueryRowContext(r.Context(),
		`UPDATE ctem_cycles
		    SET status = 'closed', closed_by = $3, closed_at = NOW(), updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2 AND status = 'review'
		 RETURNING id, name, status, start_date, end_date, charter,
		           closed_by, closed_at, created_by, created_at, updated_at`,
		tenantID, id, userID,
	).Scan(
		&c.ID, &c.Name, &c.Status, &startDate, &endDate, &charter,
		&closedBy, &closedAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.BadRequest("cycle not found or not in review status").WriteJSON(w)
			return
		}
		h.logger.Error("ctem cycle close", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	c.StartDate = startDate.String
	c.EndDate = endDate.String
	c.ClosedBy = closedBy.String
	if closedAt.Valid {
		c.ClosedAt = &closedAt.Time
	}
	if charter != nil {
		_ = json.Unmarshal(charter, &c.Charter)
	}
	if c.Charter == nil {
		c.Charter = map[string]any{}
	}

	writeJSON(w, http.StatusOK, c)
}

// GetScope retrieves the scope snapshot for a cycle.
func (h *CTEMCycleHandler) GetScope(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Verify cycle belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM ctem_cycles WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("cycle not found").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, asset_id, scope_target_id, included_at
		   FROM ctem_cycle_scope_snapshots
		  WHERE cycle_id = $1
		  ORDER BY included_at`,
		id,
	)
	if err != nil {
		h.logger.Error("ctem cycle get scope", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer rows.Close() //nolint:errcheck

	items := make([]CTEMScopeSnapshotResponse, 0)
	for rows.Next() {
		var s CTEMScopeSnapshotResponse
		var scopeTargetID sql.NullString
		if err := rows.Scan(&s.ID, &s.AssetID, &scopeTargetID, &s.IncludedAt); err != nil {
			h.logger.Error("ctem cycle scope scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		s.ScopeTargetID = scopeTargetID.String
		items = append(items, s)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ctem cycle scope rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, items)
}

// LinkProfile links an attacker profile to a cycle.
func (h *CTEMCycleHandler) LinkProfile(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		ProfileIDs []string `json:"profile_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Verify cycle belongs to tenant
	var exists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM ctem_cycles WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&exists); err != nil || !exists {
		apierror.NotFound("cycle not found").WriteJSON(w)
		return
	}

	// Link only profiles that belong to the same tenant
	for _, profileID := range req.ProfileIDs {
		_, err := h.db.ExecContext(r.Context(),
			`INSERT INTO ctem_cycle_attacker_profiles (cycle_id, profile_id)
			 SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM attacker_profiles WHERE id = $2 AND tenant_id = $3)
			 ON CONFLICT DO NOTHING`,
			id, profileID, tenantID,
		)
		if err != nil {
			h.logger.Error("ctem cycle link profile", "error", err, "profile_id", profileID)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Internal Helpers ───

// transitionStatus performs a state transition on a cycle.
func (h *CTEMCycleHandler) transitionStatus(
	r *http.Request,
	w http.ResponseWriter,
	tenantID, id, fromStatus, toStatus string,
) (CTEMCycleResponse, error) {
	row := h.db.QueryRowContext(r.Context(),
		`UPDATE ctem_cycles
		    SET status = $4, updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2 AND status = $3
		 RETURNING id, name, status, start_date, end_date, charter,
		           closed_by, closed_at, created_by, created_at, updated_at`,
		tenantID, id, fromStatus, toStatus,
	)

	c, err := h.scanCycle(row)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.BadRequest("cycle not found or not in " + fromStatus + " status").WriteJSON(w)
			return c, err
		}
		h.logger.Error("ctem cycle transition", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return c, err
	}

	return c, nil
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scan logic.
type ctemRowScanner interface {
	Scan(dest ...any) error
}

// scanCycle scans a cycle row into a response struct.
func (h *CTEMCycleHandler) scanCycle(scanner ctemRowScanner) (CTEMCycleResponse, error) {
	var c CTEMCycleResponse
	var startDate, endDate sql.NullString
	var closedBy sql.NullString
	var closedAt sql.NullTime
	var charter []byte

	err := scanner.Scan(
		&c.ID, &c.Name, &c.Status, &startDate, &endDate, &charter,
		&closedBy, &closedAt, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return c, err
	}
	c.StartDate = startDate.String
	c.EndDate = endDate.String
	c.ClosedBy = closedBy.String
	if closedAt.Valid {
		c.ClosedAt = &closedAt.Time
	}
	if charter != nil {
		_ = json.Unmarshal(charter, &c.Charter)
	}
	if c.Charter == nil {
		c.Charter = map[string]any{}
	}

	return c, nil
}


// ─── Request/Response Types ───

// CreateCTEMCycleRequest is the request body for creating/updating a CTEM cycle.
type CreateCTEMCycleRequest struct {
	Name      string         `json:"name"`
	StartDate string         `json:"start_date"`
	EndDate   string         `json:"end_date"`
	Charter   map[string]any `json:"charter"`
}

// CTEMCycleResponse is the JSON response for a CTEM cycle.
type CTEMCycleResponse struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	StartDate string         `json:"start_date,omitempty"`
	EndDate   string         `json:"end_date,omitempty"`
	Charter   map[string]any `json:"charter"`
	ClosedBy  string         `json:"closed_by,omitempty"`
	ClosedAt  *time.Time     `json:"closed_at,omitempty"`
	CreatedBy string         `json:"created_by"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CTEMScopeSnapshotResponse is the JSON response for a scope snapshot entry.
type CTEMScopeSnapshotResponse struct {
	ID            string    `json:"id"`
	AssetID       string    `json:"asset_id"`
	ScopeTargetID string    `json:"scope_target_id,omitempty"`
	IncludedAt    time.Time `json:"included_at"`
}
