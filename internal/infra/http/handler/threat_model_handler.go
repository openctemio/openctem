package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/threatmodel"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatModelHandler serves the continuous threat-modeling endpoints: list
// models per scope, read a model with its enumerated threats, and trigger a
// (re)generation for a scope.
type ThreatModelHandler struct {
	service *threatmodel.Service
	logger  *logger.Logger
}

// NewThreatModelHandler creates a ThreatModelHandler.
func NewThreatModelHandler(service *threatmodel.Service, log *logger.Logger) *ThreatModelHandler {
	return &ThreatModelHandler{service: service, logger: log.With("handler", "threat_model")}
}

// ---- responses -------------------------------------------------------------

// ThreatModelResponse is the JSON projection of a threat model (rollups only).
type ThreatModelResponse struct {
	ID                      string    `json:"id"`
	TenantID                string    `json:"tenant_id"`
	ScopeType               string    `json:"scope_type"`
	ScopeRefID              string    `json:"scope_ref_id,omitempty"`
	Name                    string    `json:"name"`
	GeneratedAt             time.Time `json:"generated_at"`
	InputHash               string    `json:"input_hash,omitempty"`
	TechniqueDatasetVersion string    `json:"technique_dataset_version"`
	ThreatsTotal            int       `json:"threats_total"`
	ThreatsOpen             int       `json:"threats_open"`
	ThreatsMitigated        int       `json:"threats_mitigated"`
	ThreatsCovered          int       `json:"threats_covered"`
	CoveragePct             float64   `json:"coverage_pct"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// ThreatResponse is the JSON projection of one enumerated threat.
type ThreatResponse struct {
	ID                string  `json:"id"`
	AttackerProfileID string  `json:"attacker_profile_id,omitempty"`
	EntryPointAssetID string  `json:"entry_point_asset_id,omitempty"`
	TargetAssetID     string  `json:"target_asset_id,omitempty"`
	HopAssetID        string  `json:"hop_asset_id,omitempty"`
	HopIndex          int     `json:"hop_index"`
	ChainFingerprint  string  `json:"chain_fingerprint"`
	TechniqueID       string  `json:"technique_id"`
	Tactic            string  `json:"tactic,omitempty"`
	MitigationID      string  `json:"mitigation_id,omitempty"`
	Status            string  `json:"status"`
	StatusReason      string  `json:"status_reason,omitempty"`
	EvidenceFindingID string  `json:"evidence_finding_id,omitempty"`
	Score             float64 `json:"score"`
}

// ThreatModelDetailResponse is a model plus its threats.
type ThreatModelDetailResponse struct {
	ThreatModelResponse
	Threats []ThreatResponse `json:"threats"`
}

// ---- coverage responses ----------------------------------------------------

// CoverageStatusCounts is the per-status threat breakdown for a technique cell.
type CoverageStatusCounts struct {
	Open        int `json:"open"`
	Mitigated   int `json:"mitigated"`
	Covered     int `json:"covered"`
	Accepted    int `json:"accepted"`
	Theoretical int `json:"theoretical"`
}

// CoverageTechniqueResponse is one technique cell of the coverage matrix.
type CoverageTechniqueResponse struct {
	TechniqueID   string               `json:"technique_id"`
	TechniqueName string               `json:"technique_name,omitempty"`
	Status        string               `json:"status"`
	Counts        CoverageStatusCounts `json:"counts"`
	MaxScore      float64              `json:"max_score"`
	MitigationIDs []string             `json:"mitigation_ids,omitempty"`
	ThreatCount   int                  `json:"threat_count"`
}

// CoverageTacticResponse groups technique cells under a tactic.
type CoverageTacticResponse struct {
	Tactic     string                      `json:"tactic"`
	Techniques []CoverageTechniqueResponse `json:"techniques"`
}

// CoverageTotalsResponse is the model-wide rollup over technique cells.
type CoverageTotalsResponse struct {
	Techniques  int     `json:"techniques"`
	Open        int     `json:"open"`
	Mitigated   int     `json:"mitigated"`
	Covered     int     `json:"covered"`
	Accepted    int     `json:"accepted"`
	Theoretical int     `json:"theoretical"`
	CoveragePct float64 `json:"coverage_pct"`
}

// ThreatModelCoverageResponse is the tactic × technique coverage matrix payload.
// The UI colors a heatmap by per-technique status and can map technique_id +
// status/max_score to an ATT&CK Navigator layer client-side.
type ThreatModelCoverageResponse struct {
	ThreatModelID  string                   `json:"threat_model_id"`
	ScopeType      string                   `json:"scope_type"`
	ScopeRefID     string                   `json:"scope_ref_id,omitempty"`
	DatasetVersion string                   `json:"dataset_version"`
	GeneratedAt    time.Time                `json:"generated_at"`
	Tactics        []CoverageTacticResponse `json:"tactics"`
	Totals         CoverageTotalsResponse   `json:"totals"`
}

// GenerateThreatModelRequest is the body for POST /threat-models/generate.
type GenerateThreatModelRequest struct {
	ScopeType  string `json:"scope_type"`
	ScopeRefID string `json:"scope_ref_id"`
}

// ---- handlers --------------------------------------------------------------

// List returns the tenant's threat models, filterable by scope, paginated.
func (h *ThreatModelHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}

	perPage := parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage)
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	var filter tmdom.ModelFilter
	if st := r.URL.Query().Get("scope_type"); st != "" {
		filter.ScopeType = tmdom.ScopeType(st)
	}
	if ref := r.URL.Query().Get("scope_ref_id"); ref != "" {
		if id, err := shared.IDFromString(ref); err == nil {
			filter.ScopeRefID = &id
		}
	}

	models, total, err := h.service.List(r.Context(), tenantID, filter, page)
	if err != nil {
		h.logger.Error("list threat models", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	items := make([]ThreatModelResponse, len(models))
	for i, m := range models {
		items[i] = toModelResponse(m)
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(items, int64(total), page))
}

// Get returns a model and its threats, filterable by status / attacker / tactic.
func (h *ThreatModelHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid threat model id").WriteJSON(w)
		return
	}

	var filter tmdom.ThreatFilter
	if st := r.URL.Query().Get("status"); st != "" {
		filter.Status = tmdom.ThreatStatus(st)
	}
	if ap := r.URL.Query().Get("attacker_profile_id"); ap != "" {
		if aid, aerr := shared.IDFromString(ap); aerr == nil {
			filter.AttackerProfileID = &aid
		}
	}
	filter.Tactic = r.URL.Query().Get("tactic")
	filter.TechniqueID = r.URL.Query().Get("technique_id")

	model, threats, err := h.service.Get(r.Context(), tenantID, id, filter)
	if err != nil {
		if errors.Is(err, tmdom.ErrNotFound) {
			apierror.NotFound("threat model not found").WriteJSON(w)
			return
		}
		h.logger.Error("get threat model", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}

	resp := ThreatModelDetailResponse{
		ThreatModelResponse: toModelResponse(model),
		Threats:             make([]ThreatResponse, len(threats)),
	}
	for i, t := range threats {
		resp.Threats[i] = toThreatResponse(t)
	}
	writeJSON(w, http.StatusOK, resp)
}

// Coverage returns the model's tactic × technique coverage matrix (worst-case
// status rollup per technique, per-status counts, totals + coverage_pct).
func (h *ThreatModelHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid threat model id").WriteJSON(w)
		return
	}

	model, cov, err := h.service.Coverage(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, tmdom.ErrNotFound) {
			apierror.NotFound("threat model not found").WriteJSON(w)
			return
		}
		h.logger.Error("threat model coverage", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toCoverageResponse(model, cov))
}

// Generate (re)generates the model for a scope and returns it.
func (h *ThreatModelHandler) Generate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}

	var req GenerateThreatModelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	scopeType := tmdom.ScopeType(req.ScopeType)
	if !scopeType.Valid() {
		apierror.BadRequest("invalid scope_type").WriteJSON(w)
		return
	}
	var scopeRefID *shared.ID
	if req.ScopeRefID != "" {
		id, err := shared.IDFromString(req.ScopeRefID)
		if err != nil {
			apierror.BadRequest("invalid scope_ref_id").WriteJSON(w)
			return
		}
		scopeRefID = &id
	}

	model, err := h.service.GenerateForScope(r.Context(), tenantID, scopeType, scopeRefID)
	if err != nil {
		if errors.Is(err, shared.ErrValidation) || errors.Is(err, tmdom.ErrInvalidScope) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("scope reference not found").WriteJSON(w)
			return
		}
		h.logger.Error("generate threat model", "error", err)
		apierror.InternalServerError("generation failed").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusCreated, toModelResponse(model))
}

func (h *ThreatModelHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return shared.ID{}, false
	}
	return tenantID, true
}

func toModelResponse(m *tmdom.ThreatModel) ThreatModelResponse {
	resp := ThreatModelResponse{
		ID:                      m.ID.String(),
		TenantID:                m.TenantID.String(),
		ScopeType:               m.ScopeType.String(),
		Name:                    m.Name,
		GeneratedAt:             m.GeneratedAt,
		InputHash:               m.InputHash,
		TechniqueDatasetVersion: m.TechniqueDatasetVersion,
		ThreatsTotal:            m.ThreatsTotal,
		ThreatsOpen:             m.ThreatsOpen,
		ThreatsMitigated:        m.ThreatsMitigated,
		ThreatsCovered:          m.ThreatsCovered,
		CoveragePct:             m.CoveragePct,
		CreatedAt:               m.CreatedAt,
		UpdatedAt:               m.UpdatedAt,
	}
	if m.ScopeRefID != nil {
		resp.ScopeRefID = m.ScopeRefID.String()
	}
	return resp
}

func toCoverageResponse(m *tmdom.ThreatModel, cov threatmodel.Coverage) ThreatModelCoverageResponse {
	resp := ThreatModelCoverageResponse{
		ThreatModelID:  m.ID.String(),
		ScopeType:      m.ScopeType.String(),
		DatasetVersion: m.TechniqueDatasetVersion,
		GeneratedAt:    m.GeneratedAt,
		Tactics:        make([]CoverageTacticResponse, len(cov.Tactics)),
		Totals: CoverageTotalsResponse{
			Techniques:  cov.Totals.Techniques,
			Open:        cov.Totals.Open,
			Mitigated:   cov.Totals.Mitigated,
			Covered:     cov.Totals.Covered,
			Accepted:    cov.Totals.Accepted,
			Theoretical: cov.Totals.Theoretical,
			CoveragePct: cov.Totals.CoveragePct,
		},
	}
	if m.ScopeRefID != nil {
		resp.ScopeRefID = m.ScopeRefID.String()
	}
	for i, tac := range cov.Tactics {
		techs := make([]CoverageTechniqueResponse, len(tac.Techniques))
		for j, tc := range tac.Techniques {
			techs[j] = CoverageTechniqueResponse{
				TechniqueID:   tc.TechniqueID,
				TechniqueName: tc.TechniqueName,
				Status:        tc.Status,
				Counts: CoverageStatusCounts{
					Open:        tc.Counts.Open,
					Mitigated:   tc.Counts.Mitigated,
					Covered:     tc.Counts.Covered,
					Accepted:    tc.Counts.Accepted,
					Theoretical: tc.Counts.Theoretical,
				},
				MaxScore:      tc.MaxScore,
				MitigationIDs: tc.MitigationIDs,
				ThreatCount:   tc.ThreatCount,
			}
		}
		resp.Tactics[i] = CoverageTacticResponse{Tactic: tac.Tactic, Techniques: techs}
	}
	return resp
}

func toThreatResponse(t *tmdom.ThreatModelThreat) ThreatResponse {
	resp := ThreatResponse{
		ID:               t.ID.String(),
		HopIndex:         t.HopIndex,
		ChainFingerprint: t.ChainFingerprint,
		TechniqueID:      t.TechniqueID,
		Tactic:           t.Tactic,
		MitigationID:     t.MitigationID,
		Status:           t.Status.String(),
		StatusReason:     t.StatusReason,
		Score:            t.Score,
	}
	if t.AttackerProfileID != nil {
		resp.AttackerProfileID = t.AttackerProfileID.String()
	}
	if t.EntryPointAssetID != nil {
		resp.EntryPointAssetID = t.EntryPointAssetID.String()
	}
	if t.TargetAssetID != nil {
		resp.TargetAssetID = t.TargetAssetID.String()
	}
	if t.HopAssetID != nil {
		resp.HopAssetID = t.HopAssetID.String()
	}
	if t.EvidenceFindingID != nil {
		resp.EvidenceFindingID = t.EvidenceFindingID.String()
	}
	return resp
}
