package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CoverageReader returns per-severity validation coverage for a tenant plus the
// confirm-or-downgrade outcome counts. Implemented by
// *postgres.ValidationEvidenceRepository.
type CoverageReader interface {
	CoverageBySeverity(ctx context.Context, tenantID shared.ID) ([]validation.SeverityCoverage, error)
	// DowngradeStats returns (downgraded, validated) for the downgrade % metric.
	DowngradeStats(ctx context.Context, tenantID shared.ID) (downgraded, validated int, err error)
	// CoverageByPriority is the CTEM-cycle definition of validation coverage
	// (closed findings per priority class with validation evidence), tenant-wide.
	CoverageByPriority(ctx context.Context, tenantID string) (validation.ValidationCoverage, error)
}

// priorityCoverageOut is one priority class of the tenant-wide coverage.
type priorityCoverageOut struct {
	Priority  string `json:"priority"`
	Total     int    `json:"total"`
	Validated int    `json:"validated"`
}

// ValidationHandler exposes CTEM Stage-4 validation evidence:
//   - sensors POST validation/proof-of-fix evidence for a finding (API-key auth)
//   - users GET the evidence recorded for a finding (JWT auth, findings:read)
//   - users GET tenant validation coverage by severity (the Validation KPI)
//
// The sensor path is tenant-scoped via the authenticated sensor's tenant — the
// handler NEVER accepts a tenant override from the body, so a compromised sensor
// cannot write into another tenant.
type ValidationHandler struct {
	ingest   *validation.EvidenceIngestService
	coverage CoverageReader
	commands ValidationCommandLookup
	policy   EvidencePolicyReader
	logger   *logger.Logger
}

// EvidencePolicyReader reads the tenant's policy for sensor results without a
// command (RFC-040 §5.3), which says whether advisory evidence is accepted.
// Implemented by *ingest.Service.
type EvidencePolicyReader interface {
	ResultPolicy(ctx context.Context, tenantID shared.ID) sensorresult.Policy
}

// SetEvidencePolicy wires the policy reader. Unset, advisory evidence (no
// command_id) is refused.
func (h *ValidationHandler) SetEvidencePolicy(p EvidencePolicyReader) { h.policy = p }

// ValidationCommandLookup resolves the validate command a sensor cites as its
// authority to submit evidence. Implemented by *postgres.CommandRepository.
type ValidationCommandLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*commanddom.Command, error)
}

// SetCommandLookup wires the command store used to authorize evidence that
// cites a command_id. When unset, evidence that cites one is refused.
func (h *ValidationHandler) SetCommandLookup(c ValidationCommandLookup) { h.commands = c }

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

// evidenceRequest is the sensor-submitted validation result.
type evidenceRequest struct {
	FindingID string `json:"finding_id"`
	// CommandID is the validate command (assigned to the submitting sensor, not
	// yet finished, for this finding) that authorizes the evidence to change
	// the finding's status. Required unless the tenant's sensor result policy
	// allows advisory evidence (RFC-040 §5.3); the evidence is then recorded
	// as advisory only (no status change).
	CommandID       string           `json:"command_id,omitempty"`
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
	// Downgraded is true when a not_reproducible verdict downgraded a still-open
	// finding to validated_fixed (RFC-011.2 confirm-or-downgrade).
	Downgraded bool `json:"downgraded"`
}

// IngestEvidence handles POST /api/v1/validation/evidence (sensor API-key auth).
func (h *ValidationHandler) IngestEvidence(w http.ResponseWriter, r *http.Request) {
	agt := SensorFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("sensor authentication required").WriteJSON(w)
		return
	}
	if agt.TenantID == nil {
		// Platform sensors are not tenant-scoped — validation evidence is.
		apierror.Forbidden("a tenant-scoped sensor is required").WriteJSON(w)
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

	// Authorization: only evidence backed by the validate command assigned to
	// THIS sensor for THIS finding may move the finding's status. Previously any
	// sensor key in the tenant could resolve / downgrade / reopen any finding by
	// posting an outcome for its id.
	authorized := false
	if req.CommandID == "" && (h.policy == nil || !h.policy.ResultPolicy(r.Context(), tenantID).AllowAdvisoryEvidence) {
		// RFC-040 §5.3: evidence without the validate command assigned to
		// this sensor is refused unless an administrator allowed advisory
		// evidence for the tenant.
		h.logger.Warn("validation evidence refused: no command_id and advisory evidence is off",
			"sensor_id", agt.ID.String(), "finding_id", findingID.String())
		apierror.New(http.StatusForbidden, "COMMAND_REQUIRED",
			"Evidence must cite the validate command assigned to this sensor (command_id).").WriteJSON(w)
		return
	}
	if req.CommandID != "" {
		cmd, ok := h.authorizeEvidenceCommand(r.Context(), w, agt.ID, tenantID, findingID, req.CommandID)
		if !ok {
			return
		}
		authorized = true
		ev.CorrelationID = cmd.ID
		// A retest check (RFC-039) never moves the finding on its own: the
		// retest service reads both of the retest's commands when they
		// complete. Its evidence is recorded, not applied.
		var payload validation.ValidateCommandPayload
		if json.Unmarshal(cmd.Payload, &payload) == nil && payload.RetestID != "" {
			authorized = false
		}
	}

	var result validation.IngestResult
	if authorized {
		result, err = h.ingest.Ingest(r.Context(), tenantID, findingID, simRunID, ev)
	} else {
		h.logger.Info("validation evidence recorded as advisory (no assigned validate command cited)",
			"sensor_id", agt.ID.String(), "finding_id", findingID.String())
		result, err = h.ingest.IngestAdvisory(r.Context(), tenantID, findingID, simRunID, ev)
	}
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
		Downgraded:    result.Downgraded,
	})
}

// authorizeEvidenceCommand checks that commandID names a validate command in
// the sensor's tenant, assigned to this sensor, still in flight, whose payload
// targets findingID. Writes the error response and returns false otherwise.
// Every rejection is the same generic 403 (no command-state enumeration).
func (h *ValidationHandler) authorizeEvidenceCommand(
	ctx context.Context, w http.ResponseWriter,
	sensorID, tenantID, findingID shared.ID, commandID string,
) (*commanddom.Command, bool) {
	cid, err := shared.IDFromString(commandID)
	if err != nil {
		apierror.BadRequest("command_id must be a valid id").WriteJSON(w)
		return nil, false
	}
	deny := func(reason string) (*commanddom.Command, bool) {
		h.logger.Warn("validation evidence rejected: command does not authorize it",
			"sensor_id", sensorID.String(), "command_id", sanitizeLogField(commandID),
			"finding_id", findingID.String(), "reason", reason)
		apierror.Forbidden("command does not authorize evidence for this finding").WriteJSON(w)
		return nil, false
	}
	if h.commands == nil {
		return deny("command lookup not configured")
	}
	cmd, err := h.commands.GetByTenantAndID(ctx, tenantID, cid)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return deny("not found")
		}
		h.logger.Error("validation evidence: command lookup failed", "error", err)
		apierror.InternalServerError("failed to record validation evidence").WriteJSON(w)
		return nil, false
	}
	if cmd.Type != commanddom.CommandTypeValidate {
		return deny("not a validate command")
	}
	if cmd.SensorID == nil || *cmd.SensorID != sensorID {
		return deny("not assigned to this sensor")
	}
	switch cmd.Status {
	case commanddom.CommandStatusPending, commanddom.CommandStatusAcknowledged, commanddom.CommandStatusRunning:
	default:
		return deny("command already finished")
	}
	var payload validation.ValidateCommandPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.FindingID != findingID.String() {
		return deny("command targets a different finding")
	}
	return cmd, true
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

	// DetectionStatus answers "did any control observe this validation?" —
	// a DIFFERENT question from Outcome ("is the exposure still
	// reachable?"). The value sets are disjoint on purpose; see
	// internal/app/validation/detection.go.
	//
	// Clients MUST NOT render anything other than "not_observed" as a
	// control failure. "no_telemetry_source" in particular means no
	// telemetry is reaching the platform — UNKNOWN, not a miss. Showing
	// it as a miss reports a configuration gap as a security failure.
	DetectionStatus string `json:"detection_status"`
	// DetectionIsGap is the precomputed safe predicate for the above so a
	// client cannot get the comparison wrong.
	DetectionIsGap bool `json:"detection_is_gap"`
	// DetectionDetail explains how the verdict was reached (match mode,
	// window bounds, pipeline liveness).
	DetectionDetail map[string]any `json:"detection_detail,omitempty"`
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

			DetectionStatus: string(rec.DetectionStatus),
			DetectionIsGap:  rec.DetectionStatus.IsDetectionGap(),
			DetectionDetail: rec.DetectionDetail,
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

	// Confirm-or-downgrade outcome metric (RFC-011.2 Phase 2a). This is what
	// flips the Program-Health board's downgrade % from "not measured" to live.
	// A DowngradeStats failure degrades to zeros rather than failing the whole
	// coverage KPI — the by-severity view is the primary payload here.
	downgraded, dgValidated, derr := h.coverage.DowngradeStats(r.Context(), tenantID)
	if derr != nil {
		h.logger.Error("validation downgrade stats query failed", "error", derr)
		downgraded, dgValidated = 0, 0
	}

	// Priority-class coverage: the same definition as the CTEM cycle's close
	// gate (closed P0..P3 findings with validation evidence), over all time.
	// The Validation overview headlines P0+P1. Like the downgrade stats, a
	// failure degrades to empty rather than failing the by-severity KPI.
	byPriority := []priorityCoverageOut{}
	p0p1Total, p0p1Validated := 0, 0
	if pc, perr := h.coverage.CoverageByPriority(r.Context(), tenantID.String()); perr != nil {
		h.logger.Error("validation coverage by priority query failed", "error", perr)
	} else {
		byPriority = []priorityCoverageOut{
			{Priority: "P0", Total: pc.P0Total, Validated: pc.P0WithEvidence},
			{Priority: "P1", Total: pc.P1Total, Validated: pc.P1WithEvidence},
			{Priority: "P2", Total: pc.P2Total, Validated: pc.P2WithEvidence},
			{Priority: "P3", Total: pc.P3Total, Validated: pc.P3WithEvidence},
		}
		p0p1Total = pc.P0Total + pc.P1Total
		p0p1Validated = pc.P0WithEvidence + pc.P1WithEvidence
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"by_priority":     byPriority,
		"p0_p1_total":     p0p1Total,
		"p0_p1_validated": p0p1Validated,
		"by_severity":     out,
		"total":           total,
		"validated":       validated,
		"overall_pct":     overall,
		// Downgrade outcome metric: of the findings validated, the share a
		// re-check downgraded (validated_fixed). downgrade_validated is the
		// metric's own denominator (distinct findings with any evidence).
		"downgraded":          downgraded,
		"downgrade_validated": dgValidated,
		"downgrade_pct":       validation.DowngradePct(downgraded, dgValidated),
	})
}
