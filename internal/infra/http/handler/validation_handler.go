package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// CoverageReader returns per-severity validation coverage for a tenant.
// Implemented by *postgres.ValidationEvidenceRepository.
type CoverageReader interface {
	CoverageBySeverity(ctx context.Context, tenantID shared.ID) ([]validation.SeverityCoverage, error)
}

// ValidationHandler exposes CTEM Stage-4 validation evidence:
//   - agents POST validation/proof-of-fix evidence for a finding (API-key auth)
//   - users GET the evidence recorded for a finding (JWT auth, findings:read)
//   - users GET tenant validation coverage by severity (the Validation KPI)
//
// The agent path is tenant-scoped via the authenticated agent's tenant — the
// handler NEVER accepts a tenant override from the body, so a compromised agent
// cannot write into another tenant.
type ValidationHandler struct {
	ingest   *validation.EvidenceIngestService
	coverage CoverageReader
	logger   *logger.Logger
}

// NewValidationHandler creates the handler.
func NewValidationHandler(ingest *validation.EvidenceIngestService, log *logger.Logger) *ValidationHandler {
	return &ValidationHandler{
		ingest: ingest,
		logger: log.With("handler", "validation"),
	}
}

// SetCoverageReader wires the coverage KPI source. When unset the coverage
// endpoint responds 503.
func (h *ValidationHandler) SetCoverageReader(r CoverageReader) { h.coverage = r }

// evidenceTargetIn is the wire form of validation.Target.
type evidenceTargetIn struct {
	AssetID  string         `json:"asset_id,omitempty"`
	Type     string         `json:"type,omitempty"`
	Address  string         `json:"address,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// evidenceRequest is the agent-submitted validation result.
type evidenceRequest struct {
	FindingID       string           `json:"finding_id"`
	SimulationRunID string           `json:"simulation_run_id,omitempty"`
	ExecutorKind    string           `json:"executor_kind"`
	Technique       string           `json:"technique,omitempty"`
	Target          evidenceTargetIn `json:"target"`
	Outcome         string           `json:"outcome"`
	Summary         string           `json:"summary,omitempty"`
	Artifacts       []string         `json:"artifacts,omitempty"`
	RawMeta         map[string]any   `json:"raw_meta,omitempty"`
	StartedAt       time.Time        `json:"started_at,omitempty"`
	EndedAt         time.Time        `json:"ended_at,omitempty"`
}

type evidenceResponse struct {
	EvidenceID    string `json:"evidence_id"`
	FindingID     string `json:"finding_id"`
	Outcome       string `json:"outcome"`
	StatusChanged bool   `json:"status_changed"`
}

// IngestEvidence handles POST /api/v1/validation/evidence (agent API-key auth).
func (h *ValidationHandler) IngestEvidence(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("agent authentication required").WriteJSON(w)
		return
	}
	if agt.TenantID == nil {
		// Platform agents are not tenant-scoped — validation evidence is.
		apierror.Forbidden("a tenant-scoped agent is required").WriteJSON(w)
		return
	}
	tenantID := *agt.TenantID

	var req evidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid JSON body").WriteJSON(w)
		return
	}

	findingID, err := shared.IDFromString(req.FindingID)
	if err != nil {
		apierror.BadRequest("finding_id must be a valid id").WriteJSON(w)
		return
	}
	if req.ExecutorKind == "" {
		apierror.BadRequest("executor_kind is required").WriteJSON(w)
		return
	}
	if req.Outcome == "" {
		apierror.BadRequest("outcome is required").WriteJSON(w)
		return
	}

	var simRunID *shared.ID
	if req.SimulationRunID != "" {
		id, sErr := shared.IDFromString(req.SimulationRunID)
		if sErr != nil {
			apierror.BadRequest("simulation_run_id must be a valid id").WriteJSON(w)
			return
		}
		simRunID = &id
	}

	target := validation.Target{
		Type:     req.Target.Type,
		Address:  req.Target.Address,
		Metadata: req.Target.Metadata,
	}
	if req.Target.AssetID != "" {
		assetID, aErr := shared.IDFromString(req.Target.AssetID)
		if aErr != nil {
			apierror.BadRequest("target.asset_id must be a valid id").WriteJSON(w)
			return
		}
		target.AssetID = assetID
	}

	ev := validation.Evidence{
		ExecutorKind: req.ExecutorKind,
		Technique:    validation.TechniqueID(req.Technique),
		Target:       target,
		StartedAt:    req.StartedAt,
		EndedAt:      req.EndedAt,
		Outcome:      validation.Outcome(req.Outcome),
		Summary:      req.Summary,
		Artifacts:    req.Artifacts,
		RawMeta:      req.RawMeta,
	}

	result, err := h.ingest.Ingest(r.Context(), tenantID, findingID, simRunID, ev)
	if err != nil {
		h.writeIngestError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(evidenceResponse{
		EvidenceID:    result.Stored.ID.String(),
		FindingID:     findingID.String(),
		Outcome:       req.Outcome,
		StatusChanged: result.StatusChanged,
	})
}

func (h *ValidationHandler) writeIngestError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("finding").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("invalid evidence").WriteJSON(w)
	default:
		h.logger.Error("validation evidence ingest failed", "error", err)
		apierror.InternalServerError("failed to record validation evidence").WriteJSON(w)
	}
}

// storedEvidenceOut is the read shape returned to UI clients.
type storedEvidenceOut struct {
	ID              string         `json:"id"`
	FindingID       string         `json:"finding_id"`
	SimulationRunID string         `json:"simulation_run_id,omitempty"`
	ExecutorKind    string         `json:"executor_kind"`
	Technique       string         `json:"technique,omitempty"`
	Outcome         string         `json:"outcome"`
	Summary         string         `json:"summary,omitempty"`
	Artifacts       []string       `json:"artifacts,omitempty"`
	RawMeta         map[string]any `json:"raw_meta,omitempty"`
	StartedAt       time.Time      `json:"started_at,omitempty"`
	EndedAt         time.Time      `json:"ended_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

// ListFindingEvidence handles GET /api/v1/findings/{id}/evidence (JWT auth).
func (h *ValidationHandler) ListFindingEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}
	findingID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid finding id").WriteJSON(w)
		return
	}

	records, err := h.ingest.ListForFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.logger.Error("list validation evidence failed", "error", err)
		apierror.InternalServerError("failed to list validation evidence").WriteJSON(w)
		return
	}

	out := make([]storedEvidenceOut, 0, len(records))
	for _, rec := range records {
		item := storedEvidenceOut{
			ID:           rec.ID.String(),
			FindingID:    rec.FindingID.String(),
			ExecutorKind: rec.Evidence.ExecutorKind,
			Technique:    string(rec.Evidence.Technique),
			Outcome:      string(rec.Evidence.Outcome),
			Summary:      rec.Evidence.Summary,
			Artifacts:    rec.Evidence.Artifacts,
			RawMeta:      rec.Evidence.RawMeta,
			StartedAt:    rec.Evidence.StartedAt,
			EndedAt:      rec.Evidence.EndedAt,
			CreatedAt:    rec.CreatedAt,
		}
		if rec.SimulationRunID != nil {
			item.SimulationRunID = rec.SimulationRunID.String()
		}
		out = append(out, item)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"evidence": out})
}

// severityCoverageOut is the read shape for one severity band.
type severityCoverageOut struct {
	Severity  string  `json:"severity"`
	Total     int     `json:"total"`
	Validated int     `json:"validated"`
	Pct       float64 `json:"pct"`
}

// Coverage handles GET /api/v1/validation/coverage — the tenant's validation
// KPI: per severity, how many findings have at least one validation evidence
// record. (JWT, findings:read.)
func (h *ValidationHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	if h.coverage == nil {
		apierror.InternalServerError("validation coverage is not configured").WriteJSON(w)
		return
	}
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}

	bands, err := h.coverage.CoverageBySeverity(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("validation coverage query failed", "error", err)
		apierror.InternalServerError("failed to compute validation coverage").WriteJSON(w)
		return
	}

	out := make([]severityCoverageOut, 0, len(bands))
	var total, validated int
	for _, b := range bands {
		out = append(out, severityCoverageOut{
			Severity:  b.Severity,
			Total:     b.Total,
			Validated: b.Validated,
			Pct:       b.Pct(),
		})
		total += b.Total
		validated += b.Validated
	}
	overall := 0.0
	if total > 0 {
		overall = float64(validated) / float64(total) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"by_severity": out,
		"total":       total,
		"validated":   validated,
		"overall_pct": overall,
	})
}
