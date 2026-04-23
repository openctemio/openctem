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

// PriorityRuleHandler handles priority override rule CRUD endpoints.
// Uses direct SQL queries for pragmatic speed (no DDD repo layer yet).
type PriorityRuleHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewPriorityRuleHandler creates a new handler.
func NewPriorityRuleHandler(db *sql.DB, log *logger.Logger) *PriorityRuleHandler {
	return &PriorityRuleHandler{db: db, logger: log}
}

type priorityRuleResponse struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	PriorityClass   string          `json:"priority_class"`
	Conditions      json.RawMessage `json:"conditions"`
	IsActive        bool            `json:"is_active"`
	EvaluationOrder int             `json:"evaluation_order"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
}

// List lists priority override rules for a tenant.
func (h *PriorityRuleHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, name, COALESCE(description,''), priority_class, conditions,
			is_active, evaluation_order, created_at, updated_at
		FROM priority_override_rules
		WHERE tenant_id = $1
		ORDER BY evaluation_order DESC, name ASC
	`, tenantID)
	if err != nil {
		h.logger.Error("list priority rules", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer func() { _ = rows.Close() }()

	result := make([]priorityRuleResponse, 0)
	for rows.Next() {
		var resp priorityRuleResponse
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&resp.ID, &resp.Name, &resp.Description, &resp.PriorityClass,
			&resp.Conditions, &resp.IsActive, &resp.EvaluationOrder,
			&createdAt, &updatedAt); err != nil {
			h.logger.Error("scan priority rule", "error", err)
			continue
		}
		resp.CreatedAt = createdAt.Format(time.RFC3339)
		resp.UpdatedAt = updatedAt.Format(time.RFC3339)
		result = append(result, resp)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":  result,
		"total": len(result),
	})
}

// Get retrieves a single priority override rule.
func (h *PriorityRuleHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var resp priorityRuleResponse
	var createdAt, updatedAt time.Time
	err := h.db.QueryRowContext(r.Context(), `
		SELECT id, name, COALESCE(description,''), priority_class, conditions,
			is_active, evaluation_order, created_at, updated_at
		FROM priority_override_rules
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id).Scan(&resp.ID, &resp.Name, &resp.Description, &resp.PriorityClass,
		&resp.Conditions, &resp.IsActive, &resp.EvaluationOrder, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			apierror.NotFound("rule not found").WriteJSON(w)
			return
		}
		h.logger.Error("get priority rule", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	resp.CreatedAt = createdAt.Format(time.RFC3339)
	resp.UpdatedAt = updatedAt.Format(time.RFC3339)
	writeJSON(w, http.StatusOK, resp)
}

// Create creates a new priority override rule.
func (h *PriorityRuleHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req struct {
		Name            string          `json:"name"`
		Description     string          `json:"description"`
		PriorityClass   string          `json:"priority_class"`
		Conditions      json.RawMessage `json:"conditions"`
		IsActive        bool            `json:"is_active"`
		EvaluationOrder int             `json:"evaluation_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}
	if req.PriorityClass != "P0" && req.PriorityClass != "P1" &&
		req.PriorityClass != "P2" && req.PriorityClass != "P3" {
		apierror.BadRequest("priority_class must be P0, P1, P2, or P3").WriteJSON(w)
		return
	}
	if len(req.Conditions) == 0 {
		req.Conditions = []byte("[]")
	}

	var id string
	err := h.db.QueryRowContext(r.Context(), `
		INSERT INTO priority_override_rules (tenant_id, name, description, priority_class,
			conditions, is_active, evaluation_order, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, tenantID, req.Name, req.Description, req.PriorityClass,
		req.Conditions, req.IsActive, req.EvaluationOrder, userID,
	).Scan(&id)
	if err != nil {
		h.logger.Error("create priority rule", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// Update updates a priority override rule.
func (h *PriorityRuleHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		Name            *string          `json:"name"`
		Description     *string          `json:"description"`
		PriorityClass   *string          `json:"priority_class"`
		Conditions      *json.RawMessage `json:"conditions"`
		IsActive        *bool            `json:"is_active"`
		EvaluationOrder *int             `json:"evaluation_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	result, err := h.db.ExecContext(r.Context(), `
		UPDATE priority_override_rules SET
			name = COALESCE($3, name),
			description = COALESCE($4, description),
			priority_class = COALESCE($5, priority_class),
			conditions = COALESCE($6, conditions),
			is_active = COALESCE($7, is_active),
			evaluation_order = COALESCE($8, evaluation_order),
			updated_by = $9,
			updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, id, req.Name, req.Description, req.PriorityClass,
		req.Conditions, req.IsActive, req.EvaluationOrder, userID)
	if err != nil {
		h.logger.Error("update priority rule", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		apierror.NotFound("rule not found").WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a priority override rule.
func (h *PriorityRuleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	result, err := h.db.ExecContext(r.Context(),
		"DELETE FROM priority_override_rules WHERE tenant_id = $1 AND id = $2",
		tenantID, id,
	)
	if err != nil {
		h.logger.Error("delete priority rule", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		apierror.NotFound("rule not found").WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
