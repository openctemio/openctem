package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app"
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
// On activation, the current scope is snapshot into ctem_cycle_scope_snapshots —
// this freezes what was in-scope at the moment the cycle started, per RFC-005 Gap 3.
//
// P0-3: scope_target_id is no longer dead. When the cycle's Charter specifies
// `in_scope_services` (business-service IDs), the snapshot is filtered to
// assets linked to those services via `business_service_assets`. Each
// snapshot row records which business service pulled it in (scope_target_id),
// enabling per-service cycle metrics and CTEM-correct targeted scoping
// instead of "freeze everything the tenant owns".
//
// Fallback: when `in_scope_services` is empty, behaviour is unchanged —
// every tenant asset is snapshotted and scope_target_id is NULL.
func (h *CTEMCycleHandler) Activate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	c, err := h.transitionStatus(r, w, tenantID, id, "planning", "active")
	if err != nil {
		return // error already written
	}

	// Pull the Charter so we can read in_scope_services. The charter is
	// stored as JSONB on ctem_cycles.
	var charterRaw []byte
	if err := h.db.QueryRowContext(r.Context(),
		`SELECT charter FROM ctem_cycles WHERE id = $1 AND tenant_id = $2`,
		id, tenantID,
	).Scan(&charterRaw); err != nil {
		h.logger.Warn("cycle charter fetch failed; falling back to all-assets snapshot",
			"cycle_id", id, "error", err)
		charterRaw = nil
	}
	inScopeServices := extractInScopeServices(charterRaw)

	var (
		result     sql.Result
		snapErr    error
		scopedRows int64
	)

	if len(inScopeServices) > 0 {
		// Targeted scope: only assets linked to the named business services.
		// scope_target_id = the business_service_id that selected the asset.
		// ON CONFLICT (cycle_id, asset_id) keeps the first service that
		// included the asset so a composite unique index would dedupe.
		scopedQuery := `
			INSERT INTO ctem_cycle_scope_snapshots (cycle_id, asset_id, scope_target_id)
			SELECT $1, bsa.asset_id, bsa.service_id
			  FROM business_service_assets bsa
			  JOIN assets a ON a.id = bsa.asset_id AND a.tenant_id = $2
			 WHERE bsa.service_id = ANY($3::uuid[])
			ON CONFLICT DO NOTHING
		`
		result, snapErr = h.db.ExecContext(r.Context(), scopedQuery, id, tenantID, pq.Array(inScopeServices))
	} else {
		// No scope filter declared → legacy behaviour: freeze every asset.
		allQuery := `
			INSERT INTO ctem_cycle_scope_snapshots (cycle_id, asset_id)
			SELECT $1, id FROM assets WHERE tenant_id = $2
			ON CONFLICT DO NOTHING
		`
		result, snapErr = h.db.ExecContext(r.Context(), allQuery, id, tenantID)
	}

	if snapErr != nil {
		h.logger.Error("cycle scope snapshot failed", "cycle_id", id, "error", snapErr)
		// Don't fail the transition — cycle is activated, snapshot can be retried
	} else if result != nil {
		scopedRows, _ = result.RowsAffected()
		h.logger.Info("cycle activated with scope snapshot",
			"cycle_id", id,
			"assets_snapshotted", scopedRows,
			"scope_mode", scopeModeLabel(inScopeServices),
			"services_in_scope", len(inScopeServices),
		)
	}

	writeJSON(w, http.StatusOK, c)
}

// extractInScopeServices reads Charter.in_scope_services from raw JSONB.
// Returns nil on any parse failure so the caller falls back to the "all
// assets" snapshot path rather than activating with an empty scope.
func extractInScopeServices(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var charter struct {
		InScopeServices []string `json:"in_scope_services"`
	}
	if err := json.Unmarshal(raw, &charter); err != nil {
		return nil
	}
	// Filter out empty strings defensively.
	out := make([]string, 0, len(charter.InScopeServices))
	for _, s := range charter.InScopeServices {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func scopeModeLabel(inScope []string) string {
	if len(inScope) > 0 {
		return "targeted"
	}
	return "all-tenant-assets"
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
//
// gate: before closing, compute validation-evidence coverage
// for findings that reached a terminal state within the cycle window.
// If any enforced priority class is under its SLO threshold, the
// close is rejected with 422 so the operator can either attach
// evidence or explicitly accept the breach (future: cycle charter).
//
// Enforcement mode is controlled by env CTEM_ENFORCE_COVERAGE_SLO
// (default: false → advisory). This preserves compatibility while
// the evidence-store rollout is in progress; flip to true once every
// tenant has the simulation_evidence table populated.
func (h *CTEMCycleHandler) Close(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := chi.URLParam(r, "id")

	// Load cycle window first — need start_date/end_date for coverage query.
	var cycleStart, cycleEnd sql.NullString
	if err := h.db.QueryRowContext(r.Context(),
		`SELECT start_date, end_date FROM ctem_cycles
		  WHERE tenant_id = $1 AND id = $2 AND status = 'review'`,
		tenantID, id,
	).Scan(&cycleStart, &cycleEnd); err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			apierror.BadRequest("cycle not found or not in review status").WriteJSON(w)
			return
		}
		h.logger.Error("ctem cycle close: load window", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	// Compute coverage and apply SLO.
	coverage, covErr := h.computeValidationCoverage(r.Context(), tenantID, cycleStart.String, cycleEnd.String)
	if covErr != nil {
		h.logger.Warn("validation coverage query failed; allowing close",
			"cycle_id", id, "error", covErr)
	} else if sloErr := app.Enforce(coverage, app.DefaultThresholds); sloErr != nil {
		enforce := os.Getenv("CTEM_ENFORCE_COVERAGE_SLO") == "true"
		if enforce {
			h.logger.Warn("cycle close blocked by coverage SLO",
				"cycle_id", id, "tenant_id", tenantID, "breach", sloErr.Error())
			apierror.BadRequest(sloErr.Error()).WriteJSON(w)
			return
		}
		// Advisory mode: log so operators can see the gap without being blocked.
		h.logger.Warn("cycle close: coverage SLO below threshold (advisory, not enforced)",
			"cycle_id", id, "tenant_id", tenantID, "breach", sloErr.Error())
	}

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

// computeValidationCoverage counts, for findings that reached a
// terminal state (resolved | verified | accepted | false_positive)
// within the cycle window, how many have a validation evidence
// record attached.
//
// The evidence source is currently the pentest_findings.evidence
// JSONB column (non-empty array = evidence present). When the
// dedicated simulation_evidence table lands (see
// internal/app/validation/evidence_store.go), this query should be
// extended with a UNION to include scripted/agent evidence.
//
// An empty cycle window (NULL start/end) means "everything to date" —
// the query uses IS NULL guards so the cycle's intent survives even
// when dates were never set.
func (h *CTEMCycleHandler) computeValidationCoverage(
	ctx context.Context,
	tenantID, startDate, endDate string,
) (app.ValidationCoverage, error) {
	var c app.ValidationCoverage
	// Build date-window clause tolerating empty strings.
	windowSQL := ""
	args := []any{tenantID}
	argN := 2
	if startDate != "" {
		windowSQL += " AND f.updated_at >= $" + itoa(argN)
		args = append(args, startDate)
		argN++
	}
	if endDate != "" {
		windowSQL += " AND f.updated_at < ($" + itoa(argN) + "::date + INTERVAL '1 day')"
		args = append(args, endDate)
	}
	q := `
		SELECT
		  COALESCE(f.priority_class, '') AS pc,
		  COUNT(*) AS total,
		  SUM(CASE WHEN pf.finding_id IS NOT NULL THEN 1 ELSE 0 END) AS with_ev
		FROM findings f
		LEFT JOIN pentest_findings pf
		  ON pf.finding_id = f.id
		 AND jsonb_array_length(COALESCE(pf.evidence, '[]'::jsonb)) > 0
		WHERE f.tenant_id = $1
		  AND f.status IN ('resolved','verified','accepted','false_positive')` + windowSQL + `
		GROUP BY COALESCE(f.priority_class, '')
	`
	rows, err := h.db.QueryContext(ctx, q, args...)
	if err != nil {
		return c, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var pc string
		var total, withEv int
		if err := rows.Scan(&pc, &total, &withEv); err != nil {
			return c, err
		}
		switch pc {
		case "P0":
			c.P0Total, c.P0WithEvidence = total, withEv
		case "P1":
			c.P1Total, c.P1WithEvidence = total, withEv
		case "P2":
			c.P2Total, c.P2WithEvidence = total, withEv
		case "P3":
			c.P3Total, c.P3WithEvidence = total, withEv
		}
	}
	return c, rows.Err()
}

// itoa is a tiny, allocation-free int→string for building SQL
// placeholders ($2, $3, ...). Avoids pulling in strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
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
