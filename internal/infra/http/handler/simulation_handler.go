package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// SimulationHandler handles attack simulation and control test HTTP endpoints.
type SimulationHandler struct {
	service *app.SimulationService
	logger  *logger.Logger
}

// NewSimulationHandler creates a new simulation handler.
func NewSimulationHandler(svc *app.SimulationService, log *logger.Logger) *SimulationHandler {
	return &SimulationHandler{service: svc, logger: log}
}

// ─── Simulation Endpoints ───

// ListSimulations lists all simulations for the tenant.
func (h *SimulationHandler) ListSimulations(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)
	filter := simulation.SimulationFilter{}

	if t := r.URL.Query().Get("type"); t != "" {
		st := simulation.SimulationType(t)
		filter.SimulationType = &st
	}
	if s := r.URL.Query().Get("status"); s != "" {
		ss := simulation.SimulationStatus(s)
		filter.Status = &ss
	}
	if q := r.URL.Query().Get("search"); q != "" {
		filter.Search = &q
	}

	result, err := h.service.ListSimulations(r.Context(), tenantID, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	resp := make([]SimulationResponse, 0, len(result.Data))
	for _, s := range result.Data {
		resp = append(resp, toSimulationResponse(s))
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(resp, result.Total, page))
}

// CreateSimulation creates a new simulation.
func (h *SimulationHandler) CreateSimulation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateSimulationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	sim, err := h.service.CreateSimulation(r.Context(), app.CreateSimulationInput{
		TenantID:           tenantID,
		Name:               req.Name,
		Description:        req.Description,
		SimulationType:     req.SimulationType,
		MitreTactic:        req.MitreTactic,
		MitreTechniqueID:   req.MitreTechniqueID,
		MitreTechniqueName: req.MitreTechniqueName,
		TargetAssets:       req.TargetAssets,
		Config:             req.Config,
		Tags:               req.Tags,
		ActorID:            userID,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toSimulationResponse(sim))
}

// GetSimulation retrieves a simulation by ID.
func (h *SimulationHandler) GetSimulation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	simID := chi.URLParam(r, "id")

	sim, err := h.service.GetSimulation(r.Context(), tenantID, simID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toSimulationResponse(sim))
}

// UpdateSimulation updates a simulation.
func (h *SimulationHandler) UpdateSimulation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	simID := chi.URLParam(r, "id")

	var req CreateSimulationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	sim, err := h.service.UpdateSimulation(r.Context(), app.UpdateSimulationInput{
		TenantID:           tenantID,
		SimulationID:       simID,
		Name:               req.Name,
		Description:        req.Description,
		MitreTactic:        req.MitreTactic,
		MitreTechniqueID:   req.MitreTechniqueID,
		MitreTechniqueName: req.MitreTechniqueName,
		TargetAssets:       req.TargetAssets,
		Config:             req.Config,
		Tags:               req.Tags,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toSimulationResponse(sim))
}

// DeleteSimulation deletes a simulation.
func (h *SimulationHandler) DeleteSimulation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	simID := chi.URLParam(r, "id")

	if err := h.service.DeleteSimulation(r.Context(), tenantID, simID); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunSimulation handles POST /api/v1/simulations/{id}/run.
func (h *SimulationHandler) RunSimulation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	simID := chi.URLParam(r, "id")
	actorID := middleware.GetUserID(r.Context())

	run, err := h.service.RunSimulation(r.Context(), tenantID, simID, actorID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":          run.ID().String(),
		"status":      string(run.Status()),
		"result":      string(run.Result()),
		"detection":   run.DetectionResult(),
		"prevention":  run.PreventionResult(),
		"duration_ms": run.DurationMs(),
		"output":      run.Output(),
	})
}

// ListSimulationRuns handles GET /api/v1/simulations/{id}/runs.
func (h *SimulationHandler) ListSimulationRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	simID := chi.URLParam(r, "id")

	page := pagination.New(
		parseQueryInt(r.URL.Query().Get("page"), 1),
		parseQueryInt(r.URL.Query().Get("per_page"), 20),
	)

	result, err := h.service.ListSimulationRuns(r.Context(), tenantID, simID, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	data := make([]map[string]any, 0, len(result.Data))
	for _, run := range result.Data {
		data = append(data, map[string]any{
			"id":          run.ID().String(),
			"status":      string(run.Status()),
			"result":      string(run.Result()),
			"detection":   run.DetectionResult(),
			"prevention":  run.PreventionResult(),
			"duration_ms": run.DurationMs(),
			"started_at":  run.StartedAt(),
			"completed_at": run.CompletedAt(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":        data,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	})
}

// ─── Control Test Endpoints ───

// ListControlTests lists all control tests for the tenant.
func (h *SimulationHandler) ListControlTests(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 {
		perPage = 20
	} else if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)
	filter := simulation.ControlTestFilter{}

	if f := r.URL.Query().Get("framework"); f != "" {
		filter.Framework = &f
	}
	if s := r.URL.Query().Get("status"); s != "" {
		filter.Status = &s
	}
	if q := r.URL.Query().Get("search"); q != "" {
		filter.Search = &q
	}

	result, err := h.service.ListControlTests(r.Context(), tenantID, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	resp := make([]ControlTestResponse, 0, len(result.Data))
	for _, ct := range result.Data {
		resp = append(resp, toControlTestResponse(ct))
	}

	writeJSON(w, http.StatusOK, pagination.NewResult(resp, result.Total, page))
}

// GetControlTestStats returns framework-level statistics.
func (h *SimulationHandler) GetControlTestStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetControlTestStats(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// CreateControlTest creates a new control test.
func (h *SimulationHandler) CreateControlTest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateControlTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	ct, err := h.service.CreateControlTest(r.Context(), app.CreateControlTestInput{
		TenantID:       tenantID,
		Name:           req.Name,
		Description:    req.Description,
		Framework:      req.Framework,
		ControlID:      req.ControlID,
		ControlName:    req.ControlName,
		Category:       req.Category,
		TestProcedure:  req.TestProcedure,
		ExpectedResult: req.ExpectedResult,
		RiskLevel:      req.RiskLevel,
		Tags:           req.Tags,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toControlTestResponse(ct))
}

// RecordControlTestResult records a test result.
func (h *SimulationHandler) RecordControlTestResult(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	var req RecordControlTestResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	ct, err := h.service.RecordControlTestResult(r.Context(), app.RecordControlTestResultInput{
		TenantID:   tenantID,
		ControlID:  ctID,
		Status:     req.Status,
		Evidence:   req.Evidence,
		Notes:      req.Notes,
		TestedByID: userID,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toControlTestResponse(ct))
}

// DeleteControlTest deletes a control test.
func (h *SimulationHandler) DeleteControlTest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctID := chi.URLParam(r, "id")

	if err := h.service.DeleteControlTest(r.Context(), tenantID, ctID); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Error Handling ───

func (h *SimulationHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("resource not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("simulation handler error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

// ──�� Request Types ���──

// CreateSimulationRequest is the API request for creating a simulation.
type CreateSimulationRequest struct {
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	SimulationType     string         `json:"simulation_type"`
	MitreTactic        string         `json:"mitre_tactic"`
	MitreTechniqueID   string         `json:"mitre_technique_id"`
	MitreTechniqueName string         `json:"mitre_technique_name"`
	TargetAssets       []string       `json:"target_assets"`
	Config             map[string]any `json:"config"`
	Tags               []string       `json:"tags"`
}

// CreateControlTestRequest is the API request for creating a control test.
type CreateControlTestRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Framework      string   `json:"framework"`
	ControlID      string   `json:"control_id"`
	ControlName    string   `json:"control_name"`
	Category       string   `json:"category"`
	TestProcedure  string   `json:"test_procedure"`
	ExpectedResult string   `json:"expected_result"`
	RiskLevel      string   `json:"risk_level"`
	Tags           []string `json:"tags"`
}

// RecordControlTestResultRequest is the API request for recording a test result.
type RecordControlTestResultRequest struct {
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Notes    string `json:"notes"`
}

// ─── Response Types ───

// SimulationResponse is the API response for a simulation.
type SimulationResponse struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	SimulationType     string         `json:"simulation_type"`
	Status             string         `json:"status"`
	MitreTactic        string         `json:"mitre_tactic,omitempty"`
	MitreTechniqueID   string         `json:"mitre_technique_id,omitempty"`
	MitreTechniqueName string         `json:"mitre_technique_name,omitempty"`
	TargetAssets       []string       `json:"target_assets"`
	Config             map[string]any `json:"config,omitempty"`
	ScheduleCron       string         `json:"schedule_cron,omitempty"`
	LastRunAt          *time.Time     `json:"last_run_at,omitempty"`
	TotalRuns          int            `json:"total_runs"`
	LastResult         string         `json:"last_result,omitempty"`
	DetectionRate      float64        `json:"detection_rate"`
	PreventionRate     float64        `json:"prevention_rate"`
	Tags               []string       `json:"tags"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

func toSimulationResponse(s *simulation.Simulation) SimulationResponse {
	return SimulationResponse{
		ID:                 s.ID().String(),
		Name:               s.Name(),
		Description:        s.Description(),
		SimulationType:     string(s.SimulationType()),
		Status:             string(s.Status()),
		MitreTactic:        s.MitreTactic(),
		MitreTechniqueID:   s.MitreTechniqueID(),
		MitreTechniqueName: s.MitreTechniqueName(),
		TargetAssets:       s.TargetAssets(),
		Config:             s.Config(),
		ScheduleCron:       s.ScheduleCron(),
		LastRunAt:          s.LastRunAt(),
		TotalRuns:          s.TotalRuns(),
		LastResult:         s.LastResult(),
		DetectionRate:      s.DetectionRate(),
		PreventionRate:     s.PreventionRate(),
		Tags:               s.Tags(),
		CreatedAt:          s.CreatedAt(),
		UpdatedAt:          s.UpdatedAt(),
	}
}

// ControlTestResponse is the API response for a control test.
type ControlTestResponse struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Description         string     `json:"description"`
	Framework           string     `json:"framework"`
	ControlID           string     `json:"control_id"`
	ControlName         string     `json:"control_name"`
	Category            string     `json:"category"`
	TestProcedure       string     `json:"test_procedure,omitempty"`
	ExpectedResult      string     `json:"expected_result,omitempty"`
	Status              string     `json:"status"`
	LastTestedAt        *time.Time `json:"last_tested_at,omitempty"`
	Evidence            string     `json:"evidence,omitempty"`
	Notes               string     `json:"notes,omitempty"`
	RiskLevel           string     `json:"risk_level"`
	LinkedSimulationIDs []string   `json:"linked_simulation_ids"`
	Tags                []string   `json:"tags"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func toControlTestResponse(ct *simulation.ControlTest) ControlTestResponse {
	return ControlTestResponse{
		ID:                  ct.ID().String(),
		Name:                ct.Name(),
		Description:         ct.Description(),
		Framework:           ct.Framework(),
		ControlID:           ct.ControlID(),
		ControlName:         ct.ControlName(),
		Category:            ct.Category(),
		TestProcedure:       ct.TestProcedure(),
		ExpectedResult:      ct.ExpectedResult(),
		Status:              string(ct.Status()),
		LastTestedAt:        ct.LastTestedAt(),
		Evidence:            ct.Evidence(),
		Notes:               ct.Notes(),
		RiskLevel:           ct.RiskLevel(),
		LinkedSimulationIDs: ct.LinkedSimulationIDs(),
		Tags:                ct.Tags(),
		CreatedAt:           ct.CreatedAt(),
		UpdatedAt:           ct.UpdatedAt(),
	}
}
