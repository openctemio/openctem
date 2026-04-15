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

// AttackerProfileHandler handles attacker profile CRUD endpoints.
// Uses direct SQL queries for pragmatic speed (no DDD repo layer yet).
type AttackerProfileHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewAttackerProfileHandler creates a new handler.
func NewAttackerProfileHandler(db *sql.DB, log *logger.Logger) *AttackerProfileHandler {
	return &AttackerProfileHandler{db: db, logger: log}
}

// List lists attacker profiles for the tenant.
func (h *AttackerProfileHandler) List(w http.ResponseWriter, r *http.Request) {
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
		"SELECT COUNT(*) FROM attacker_profiles WHERE tenant_id = $1", tenantID,
	).Scan(&total)
	if err != nil {
		h.logger.Error("attacker profile list count", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, name, profile_type, description, capabilities, assumptions,
		        is_default, created_by, created_at, updated_at
		   FROM attacker_profiles
		  WHERE tenant_id = $1
		  ORDER BY is_default DESC, created_at DESC
		  LIMIT $2 OFFSET $3`,
		tenantID, page.Limit(), page.Offset(),
	)
	if err != nil {
		h.logger.Error("attacker profile list", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer rows.Close() //nolint:errcheck

	items := make([]AttackerProfileResponse, 0, perPage)
	for rows.Next() {
		var p AttackerProfileResponse
		var desc, assumptions, createdBy sql.NullString
		var capabilities []byte
		if err := rows.Scan(
			&p.ID, &p.Name, &p.ProfileType, &desc, &capabilities, &assumptions,
			&p.IsDefault, &createdBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			h.logger.Error("attacker profile scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		p.Description = desc.String
		p.Assumptions = assumptions.String
		p.CreatedBy = createdBy.String
		if capabilities != nil {
			_ = json.Unmarshal(capabilities, &p.Capabilities)
		}
		if p.Capabilities == nil {
			p.Capabilities = map[string]any{}
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("attacker profile rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(items, total, page))
}

// Get retrieves a single attacker profile.
func (h *AttackerProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var p AttackerProfileResponse
	var desc, assumptions, createdBy sql.NullString
	var capabilities []byte

	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, name, profile_type, description, capabilities, assumptions,
		        is_default, created_by, created_at, updated_at
		   FROM attacker_profiles
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id,
	).Scan(
		&p.ID, &p.Name, &p.ProfileType, &desc, &capabilities, &assumptions,
		&p.IsDefault, &createdBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.NotFound("attacker profile not found").WriteJSON(w)
			return
		}
		h.logger.Error("attacker profile get", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	p.Description = desc.String
	p.Assumptions = assumptions.String
	p.CreatedBy = createdBy.String
	if capabilities != nil {
		_ = json.Unmarshal(capabilities, &p.Capabilities)
	}
	if p.Capabilities == nil {
		p.Capabilities = map[string]any{}
	}

	writeJSON(w, http.StatusOK, p)
}

// Create creates a new attacker profile.
func (h *AttackerProfileHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateAttackerProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}

	capJSON, err := json.Marshal(req.Capabilities)
	if err != nil {
		apierror.BadRequest("invalid capabilities JSON").WriteJSON(w)
		return
	}

	var p AttackerProfileResponse
	var desc, assumptions, createdBy sql.NullString
	var capBytes []byte

	err = h.db.QueryRowContext(r.Context(),
		`INSERT INTO attacker_profiles
		        (tenant_id, name, profile_type, description, capabilities, assumptions, is_default, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, name, profile_type, description, capabilities, assumptions,
		           is_default, created_by, created_at, updated_at`,
		tenantID, req.Name, req.ProfileType, req.Description, capJSON,
		req.Assumptions, req.IsDefault, nilString(userID),
	).Scan(
		&p.ID, &p.Name, &p.ProfileType, &desc, &capBytes, &assumptions,
		&p.IsDefault, &createdBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		h.logger.Error("attacker profile create", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	p.Description = desc.String
	p.Assumptions = assumptions.String
	p.CreatedBy = createdBy.String
	if capBytes != nil {
		_ = json.Unmarshal(capBytes, &p.Capabilities)
	}
	if p.Capabilities == nil {
		p.Capabilities = map[string]any{}
	}

	writeJSON(w, http.StatusCreated, p)
}

// Update updates an existing attacker profile.
func (h *AttackerProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req CreateAttackerProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	capJSON, err := json.Marshal(req.Capabilities)
	if err != nil {
		apierror.BadRequest("invalid capabilities JSON").WriteJSON(w)
		return
	}

	var p AttackerProfileResponse
	var desc, assumptions, createdBy sql.NullString
	var capBytes []byte

	err = h.db.QueryRowContext(r.Context(),
		`UPDATE attacker_profiles
		    SET name = $3, profile_type = $4, description = $5, capabilities = $6,
		        assumptions = $7, is_default = $8, updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2
		 RETURNING id, name, profile_type, description, capabilities, assumptions,
		           is_default, created_by, created_at, updated_at`,
		tenantID, id, req.Name, req.ProfileType, req.Description, capJSON,
		req.Assumptions, req.IsDefault,
	).Scan(
		&p.ID, &p.Name, &p.ProfileType, &desc, &capBytes, &assumptions,
		&p.IsDefault, &createdBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.NotFound("attacker profile not found").WriteJSON(w)
			return
		}
		h.logger.Error("attacker profile update", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	p.Description = desc.String
	p.Assumptions = assumptions.String
	p.CreatedBy = createdBy.String
	if capBytes != nil {
		_ = json.Unmarshal(capBytes, &p.Capabilities)
	}
	if p.Capabilities == nil {
		p.Capabilities = map[string]any{}
	}

	writeJSON(w, http.StatusOK, p)
}

// Delete deletes an attacker profile.
func (h *AttackerProfileHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	res, err := h.db.ExecContext(r.Context(),
		"DELETE FROM attacker_profiles WHERE tenant_id = $1 AND id = $2",
		tenantID, id,
	)
	if err != nil {
		h.logger.Error("attacker profile delete", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		apierror.NotFound("attacker profile not found").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Request/Response Types ───

// CreateAttackerProfileRequest is the request body for creating/updating an attacker profile.
type CreateAttackerProfileRequest struct {
	Name         string         `json:"name"`
	ProfileType  string         `json:"profile_type"`
	Description  string         `json:"description"`
	Capabilities map[string]any `json:"capabilities"`
	Assumptions  string         `json:"assumptions"`
	IsDefault    bool           `json:"is_default"`
}

// AttackerProfileResponse is the JSON response for an attacker profile.
type AttackerProfileResponse struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	ProfileType  string         `json:"profile_type"`
	Description  string         `json:"description"`
	Capabilities map[string]any `json:"capabilities"`
	Assumptions  string         `json:"assumptions,omitempty"`
	IsDefault    bool           `json:"is_default"`
	CreatedBy    string         `json:"created_by,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}
