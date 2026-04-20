package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// BusinessServiceHandler handles business service CRUD endpoints.
// A business service represents a business capability (Payment Processing,
// Customer Login) that spans multiple assets and is distinct from a
// business unit (which is an organizational grouping).
type BusinessServiceHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewBusinessServiceHandler creates a new BusinessServiceHandler.
func NewBusinessServiceHandler(db *sql.DB, log *logger.Logger) *BusinessServiceHandler {
	return &BusinessServiceHandler{db: db, logger: log}
}

// List lists business services for the tenant.
func (h *BusinessServiceHandler) List(w http.ResponseWriter, r *http.Request) {
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
		"SELECT COUNT(*) FROM business_services WHERE tenant_id = $1", tenantID,
	).Scan(&total)
	if err != nil {
		h.logger.Error("business service list count", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, name, description, criticality, compliance_scope,
		        handles_pii, handles_phi, handles_financial,
		        availability_target, rpo_minutes, rto_minutes,
		        owner_name, owner_email, created_at, updated_at
		   FROM business_services
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC
		  LIMIT $2 OFFSET $3`,
		tenantID, page.Limit(), page.Offset(),
	)
	if err != nil {
		h.logger.Error("business service list", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer func() { _ = rows.Close() }()

	items := make([]BusinessServiceResponse, 0, cappedPerPage(perPage))
	for rows.Next() {
		bs, err := scanBusinessService(rows)
		if err != nil {
			h.logger.Error("business service scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		items = append(items, bs)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("business service rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(items, total, page))
}

// Get retrieves a single business service.
func (h *BusinessServiceHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	row := h.db.QueryRowContext(r.Context(),
		`SELECT id, name, description, criticality, compliance_scope,
		        handles_pii, handles_phi, handles_financial,
		        availability_target, rpo_minutes, rto_minutes,
		        owner_name, owner_email, created_at, updated_at
		   FROM business_services
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id,
	)

	bs, err := scanBusinessService(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			apierror.NotFound("business service not found").WriteJSON(w)
			return
		}
		h.logger.Error("business service get", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, bs)
}

// Create creates a new business service.
func (h *BusinessServiceHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateBusinessServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}

	row := h.db.QueryRowContext(r.Context(),
		`INSERT INTO business_services
		        (tenant_id, name, description, criticality, compliance_scope,
		         handles_pii, handles_phi, handles_financial,
		         availability_target, rpo_minutes, rto_minutes,
		         owner_name, owner_email)
		 VALUES ($1, $2, $3, COALESCE(NULLIF($4,''), 'medium'), $5,
		         COALESCE($6, false), COALESCE($7, false), COALESCE($8, false),
		         $9, $10, $11, $12, $13)
		 RETURNING id, name, description, criticality, compliance_scope,
		           handles_pii, handles_phi, handles_financial,
		           availability_target, rpo_minutes, rto_minutes,
		           owner_name, owner_email, created_at, updated_at`,
		tenantID, req.Name, req.Description, req.Criticality,
		pq.StringArray(req.ComplianceScope),
		req.HandlesPII, req.HandlesPHI, req.HandlesFinancial,
		nilFloat64(req.AvailabilityTarget), nilInt(req.RPOMinutes), nilInt(req.RTOMinutes),
		req.OwnerName, req.OwnerEmail,
	)

	bs, err := scanBusinessService(row)
	if err != nil {
		h.logger.Error("business service create", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, bs)
}

// Update updates an existing business service.
func (h *BusinessServiceHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req CreateBusinessServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Name == "" {
		apierror.BadRequest("name is required").WriteJSON(w)
		return
	}

	row := h.db.QueryRowContext(r.Context(),
		`UPDATE business_services
		    SET name = $3, description = $4,
		        criticality = COALESCE(NULLIF($5,''), criticality),
		        compliance_scope = $6,
		        handles_pii = COALESCE($7, handles_pii),
		        handles_phi = COALESCE($8, handles_phi),
		        handles_financial = COALESCE($9, handles_financial),
		        availability_target = $10,
		        rpo_minutes = $11,
		        rto_minutes = $12,
		        owner_name = $13,
		        owner_email = $14,
		        updated_at = NOW()
		  WHERE tenant_id = $1 AND id = $2
		 RETURNING id, name, description, criticality, compliance_scope,
		           handles_pii, handles_phi, handles_financial,
		           availability_target, rpo_minutes, rto_minutes,
		           owner_name, owner_email, created_at, updated_at`,
		tenantID, id, req.Name, req.Description, req.Criticality,
		pq.StringArray(req.ComplianceScope),
		req.HandlesPII, req.HandlesPHI, req.HandlesFinancial,
		nilFloat64(req.AvailabilityTarget), nilInt(req.RPOMinutes), nilInt(req.RTOMinutes),
		req.OwnerName, req.OwnerEmail,
	)

	bs, err := scanBusinessService(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			apierror.NotFound("business service not found").WriteJSON(w)
			return
		}
		h.logger.Error("business service update", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, bs)
}

// Delete deletes a business service.
func (h *BusinessServiceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	res, err := h.db.ExecContext(r.Context(),
		"DELETE FROM business_services WHERE tenant_id = $1 AND id = $2",
		tenantID, id,
	)
	if err != nil {
		h.logger.Error("business service delete", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		apierror.NotFound("business service not found").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LinkAsset links an asset to a business service.
// Validates both the service and the asset belong to the tenant.
func (h *BusinessServiceHandler) LinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req struct {
		AssetID        string `json:"asset_id"`
		DependencyType string `json:"dependency_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.AssetID == "" {
		apierror.BadRequest("asset_id is required").WriteJSON(w)
		return
	}

	// Verify service belongs to tenant.
	var serviceExists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM business_services WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&serviceExists); err != nil || !serviceExists {
		apierror.NotFound("business service not found").WriteJSON(w)
		return
	}

	// Verify asset belongs to the same tenant before linking.
	var assetExists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2)",
		tenantID, req.AssetID,
	).Scan(&assetExists); err != nil || !assetExists {
		apierror.NotFound("asset not found").WriteJSON(w)
		return
	}

	_, err := h.db.ExecContext(r.Context(),
		`INSERT INTO business_service_assets (tenant_id, service_id, asset_id, dependency_type)
		 VALUES ($1, $2, $3, COALESCE(NULLIF($4,''), 'runs_on'))
		 ON CONFLICT DO NOTHING`,
		tenantID, id, req.AssetID, req.DependencyType,
	)
	if err != nil {
		h.logger.Error("business service link asset", "error", err, "asset_id", req.AssetID)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnlinkAsset removes an asset-service link.
func (h *BusinessServiceHandler) UnlinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")
	assetID := chi.URLParam(r, "assetId")

	// Verify service belongs to tenant before any mutation.
	var serviceExists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM business_services WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&serviceExists); err != nil || !serviceExists {
		apierror.NotFound("business service not found").WriteJSON(w)
		return
	}

	res, err := h.db.ExecContext(r.Context(),
		`DELETE FROM business_service_assets
		  WHERE tenant_id = $1 AND service_id = $2 AND asset_id = $3`,
		tenantID, id, assetID,
	)
	if err != nil {
		h.logger.Error("business service unlink asset", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		apierror.NotFound("link not found").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAssets lists assets linked to a business service.
func (h *BusinessServiceHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	// Verify service belongs to tenant.
	var serviceExists bool
	if err := h.db.QueryRowContext(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM business_services WHERE tenant_id = $1 AND id = $2)",
		tenantID, id,
	).Scan(&serviceExists); err != nil || !serviceExists {
		apierror.NotFound("business service not found").WriteJSON(w)
		return
	}

	rows, err := h.db.QueryContext(r.Context(),
		`SELECT bsa.asset_id, bsa.dependency_type, bsa.created_at,
		        a.name, a.asset_type
		   FROM business_service_assets bsa
		   JOIN assets a ON a.id = bsa.asset_id AND a.tenant_id = $1
		  WHERE bsa.tenant_id = $1 AND bsa.service_id = $2
		  ORDER BY bsa.created_at DESC`,
		tenantID, id,
	)
	if err != nil {
		h.logger.Error("business service list assets", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	defer func() { _ = rows.Close() }()

	items := make([]BusinessServiceAssetLink, 0)
	for rows.Next() {
		var link BusinessServiceAssetLink
		if err := rows.Scan(
			&link.AssetID, &link.DependencyType, &link.CreatedAt,
			&link.AssetName, &link.AssetType,
		); err != nil {
			h.logger.Error("business service asset scan", "error", err)
			apierror.InternalServerError("internal error").WriteJSON(w)
			return
		}
		items = append(items, link)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("business service asset rows", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, items)
}

// ─── Request/Response Types ───

// CreateBusinessServiceRequest is the request body for create/update.
type CreateBusinessServiceRequest struct {
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	Criticality        string   `json:"criticality"`
	ComplianceScope    []string `json:"compliance_scope"`
	HandlesPII         *bool    `json:"handles_pii"`
	HandlesPHI         *bool    `json:"handles_phi"`
	HandlesFinancial   *bool    `json:"handles_financial"`
	AvailabilityTarget *float64 `json:"availability_target"`
	RPOMinutes         *int     `json:"rpo_minutes"`
	RTOMinutes         *int     `json:"rto_minutes"`
	OwnerName          string   `json:"owner_name"`
	OwnerEmail         string   `json:"owner_email"`
}

// BusinessServiceResponse is the JSON response for a business service.
type BusinessServiceResponse struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	Criticality        string    `json:"criticality"`
	ComplianceScope    []string  `json:"compliance_scope"`
	HandlesPII         bool      `json:"handles_pii"`
	HandlesPHI         bool      `json:"handles_phi"`
	HandlesFinancial   bool      `json:"handles_financial"`
	AvailabilityTarget float64   `json:"availability_target,omitempty"`
	RPOMinutes         int       `json:"rpo_minutes,omitempty"`
	RTOMinutes         int       `json:"rto_minutes,omitempty"`
	OwnerName          string    `json:"owner_name,omitempty"`
	OwnerEmail         string    `json:"owner_email,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// BusinessServiceAssetLink is the JSON response describing an asset link.
type BusinessServiceAssetLink struct {
	AssetID        string    `json:"asset_id"`
	AssetName      string    `json:"asset_name"`
	AssetType      string    `json:"asset_type"`
	DependencyType string    `json:"dependency_type"`
	CreatedAt      time.Time `json:"created_at"`
}

// rowScanner matches both *sql.Row and *sql.Rows Scan signatures.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanBusinessService scans a business service row into a response DTO.
func scanBusinessService(s rowScanner) (BusinessServiceResponse, error) {
	var bs BusinessServiceResponse
	var (
		desc, criticality, ownerName, ownerEmail sql.NullString
		complianceScope                          pq.StringArray
		availabilityTarget                       sql.NullFloat64
		rpoMinutes, rtoMinutes                   sql.NullInt64
	)

	err := s.Scan(
		&bs.ID, &bs.Name, &desc, &criticality, &complianceScope,
		&bs.HandlesPII, &bs.HandlesPHI, &bs.HandlesFinancial,
		&availabilityTarget, &rpoMinutes, &rtoMinutes,
		&ownerName, &ownerEmail, &bs.CreatedAt, &bs.UpdatedAt,
	)
	if err != nil {
		return bs, err
	}

	bs.Description = desc.String
	bs.Criticality = criticality.String
	bs.ComplianceScope = []string(complianceScope)
	if bs.ComplianceScope == nil {
		bs.ComplianceScope = []string{}
	}
	bs.AvailabilityTarget = availabilityTarget.Float64
	bs.RPOMinutes = int(rpoMinutes.Int64)
	bs.RTOMinutes = int(rtoMinutes.Int64)
	bs.OwnerName = ownerName.String
	bs.OwnerEmail = ownerEmail.String
	return bs, nil
}

// nilFloat64 returns nil interface if pointer is nil, otherwise the value.
func nilFloat64(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}

// nilInt returns nil interface if pointer is nil, otherwise the value.
func nilInt(i *int) any {
	if i == nil {
		return nil
	}
	return *i
}
