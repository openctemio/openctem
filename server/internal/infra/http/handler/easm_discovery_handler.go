package handler

// Discovery management (docs/architecture/easm.md, "Discovery management"):
// the tenant's coverage work by stage, Run per stage, Run all, Abort all
// and a CSV export. The tenant is the principal's. Every route needs an
// unrestricted data scope (owner, administrator or a full-data role): the
// figures count every asset of the organization and Run and Abort act on all
// of them, so a member limited to some assets is refused (403), never shown
// organization totals.

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DiscoveryService is the discovery stages (*coverageapp.Discovery).
type DiscoveryService interface {
	Overview(ctx context.Context, tenantID shared.ID) (*coverageapp.Overview, error)
	Run(ctx context.Context, tenantID shared.ID, stages []covdom.DiscoveryStage) (*coverageapp.RunResult, error)
	AbortAll(ctx context.Context, tenantID shared.ID) (*coverageapp.AbortResult, error)
}

// DiscoveryScope resolves the caller's data scope (*datascope.Enforcer).
type DiscoveryScope interface {
	ResolveStrict(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
}

// EASMDiscoveryHandler serves /api/v1/attack-surface/discovery.
type EASMDiscoveryHandler struct {
	svc    DiscoveryService
	scope  DiscoveryScope
	audit  AttributionAuditor
	logger *logger.Logger
}

// NewEASMDiscoveryHandler creates the handler. scope must be wired: without
// it every request is refused (fail closed).
func NewEASMDiscoveryHandler(svc DiscoveryService, scope DiscoveryScope, audit AttributionAuditor, log *logger.Logger) *EASMDiscoveryHandler {
	return &EASMDiscoveryHandler{svc: svc, scope: scope, audit: audit, logger: log.With("handler", "easm-discovery")}
}

// DiscoveryRunResponse is a capability's latest coverage run.
type DiscoveryRunResponse struct {
	ID          string     `json:"id"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	TasksTotal  int        `json:"tasks_total"`
	TasksDone   int        `json:"tasks_done"`
}

// DiscoveryCapabilityResponse is one capability of a stage.
type DiscoveryCapabilityResponse struct {
	Capability    string                `json:"capability"`
	Pairs         int                   `json:"pairs"`
	Covered       int                   `json:"covered"`
	DueNow        int                   `json:"due_now"`
	Queued        int                   `json:"queued"`
	Failed        int                   `json:"failed"`
	Blocked       int                   `json:"blocked"`
	Paused        int                   `json:"paused"`
	PausedReason  string                `json:"paused_reason,omitempty"`
	LastAttemptAt *time.Time            `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time            `json:"last_success_at,omitempty"`
	LastRun       *DiscoveryRunResponse `json:"last_run,omitempty"`
}

// DiscoveryStageResponse is one stage of the discovery stages.
type DiscoveryStageResponse struct {
	// Stage: asset_discovery, exposure_scan, validation_scoping, technology_discovery.
	Stage string `json:"stage" enums:"asset_discovery,exposure_scan,validation_scoping,technology_discovery"`
	// Status: idle, running, paused (Reason says why), failed.
	Status         string     `json:"status" enums:"idle,running,paused,failed"`
	Reason         string     `json:"reason,omitempty"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	ProgressDone   int        `json:"progress_done"`
	ProgressTotal  int        `json:"progress_total"`
	ProgressUnit   string     `json:"progress_unit" enums:"tasks,pairs"`
	RunAvailableAt *time.Time `json:"run_available_at,omitempty"`
	// AutoValidatedAssets is set on validation_scoping only.
	AutoValidatedAssets *int                          `json:"auto_validated_assets,omitempty"`
	Capabilities        []DiscoveryCapabilityResponse `json:"capabilities"`
}

// DiscoveryAutoValidationResponse is the last automatic attribution pass.
type DiscoveryAutoValidationResponse struct {
	Assets      int        `json:"assets"`
	WindowStart *time.Time `json:"window_start,omitempty"`
	WindowEnd   *time.Time `json:"window_end,omitempty"`
}

// DiscoveryOverviewResponse is the tenant's discovery stages.
type DiscoveryOverviewResponse struct {
	GeneratedAt time.Time `json:"generated_at"`
	// LoopEnabled: the coverage loop runs on this server.
	LoopEnabled bool `json:"loop_enabled"`
	// CoverageEnabled: the organization's automatic coverage is on.
	CoverageEnabled bool                            `json:"coverage_enabled"`
	PassEverySecs   int                             `json:"pass_every_seconds"`
	DailyBudget     int                             `json:"daily_budget"`
	BudgetUsed      int                             `json:"budget_used"`
	AutoValidation  DiscoveryAutoValidationResponse `json:"auto_validation"`
	Stages          []DiscoveryStageResponse        `json:"stages"`
}

// DiscoveryRunNowResponse is what Run or Run all did.
type DiscoveryRunNowResponse struct {
	Started        []string `json:"started"`
	Skipped        []string `json:"skipped"`
	Capabilities   []string `json:"capabilities"`
	PairsMadeDue   int      `json:"pairs_made_due"`
	NextPassWithin int      `json:"next_pass_within_seconds"`
}

// DiscoveryAbortResponse is what Abort all did.
type DiscoveryAbortResponse struct {
	Canceled int `json:"canceled"`
	Failed   int `json:"failed"`
}

// authorize returns the principal's tenant when the caller is unrestricted.
func (h *EASMDiscoveryHandler) authorize(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	if h.scope == nil {
		apierror.FromCode(apierror.CodeDiscoveryFullDataRequired).WriteJSON(w)
		return shared.ID{}, false
	}
	scope, err := h.scope.ResolveStrict(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("discovery: resolve data scope", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the discovery stages").WriteJSON(w)
		return shared.ID{}, false
	}
	if scope.Restricted() {
		apierror.FromCode(apierror.CodeDiscoveryFullDataRequired).WriteJSON(w)
		return shared.ID{}, false
	}
	return tenantID, true
}

func (h *EASMDiscoveryHandler) actx(r *http.Request) auditapp.AuditContext {
	ctx := r.Context()
	return auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}
}

func toDiscoveryOverview(o *coverageapp.Overview) DiscoveryOverviewResponse {
	out := DiscoveryOverviewResponse{GeneratedAt: o.GeneratedAt, LoopEnabled: o.LoopEnabled, CoverageEnabled: o.CoverageEnabled,
		PassEverySecs: int(o.PassEvery.Seconds()), DailyBudget: o.DailyBudget, BudgetUsed: o.BudgetUsed,
		AutoValidation: DiscoveryAutoValidationResponse{Assets: o.AutoValidation.Assets,
			WindowStart: o.AutoValidation.WindowStart, WindowEnd: o.AutoValidation.WindowEnd},
		Stages: make([]DiscoveryStageResponse, 0, len(o.Stages))}
	for _, s := range o.Stages {
		st := DiscoveryStageResponse{Stage: string(s.Stage), Status: string(s.Status), Reason: s.Reason, LastRunAt: s.LastRunAt,
			ProgressDone: s.ProgressDone, ProgressTotal: s.ProgressTotal, ProgressUnit: s.ProgressUnit,
			Capabilities: make([]DiscoveryCapabilityResponse, 0, len(s.Capabilities))}
		if t, ok := o.RunAvailableAt[s.Stage]; ok {
			at := t
			st.RunAvailableAt = &at
		}
		if s.Stage == covdom.StageValidation {
			n := o.AutoValidation.Assets
			st.AutoValidatedAssets = &n
		}
		for _, c := range s.Capabilities {
			cr := DiscoveryCapabilityResponse{Capability: c.Capability, Pairs: c.Pairs, Covered: c.Covered, DueNow: c.DueNow,
				Queued: c.Queued, Failed: c.Failed, Blocked: c.Blocked, Paused: c.Paused, PausedReason: c.PausedReason,
				LastAttemptAt: c.LastAttemptAt, LastSuccessAt: c.LastSuccessAt}
			if c.LastRun != nil {
				cr.LastRun = &DiscoveryRunResponse{ID: c.LastRun.RunID, Status: c.LastRun.Status, CreatedAt: c.LastRun.CreatedAt,
					StartedAt: c.LastRun.StartedAt, CompletedAt: c.LastRun.CompletedAt,
					TasksTotal: c.LastRun.TasksTotal, TasksDone: c.LastRun.TasksDone}
			}
			st.Capabilities = append(st.Capabilities, cr)
		}
		out.Stages = append(out.Stages, st)
	}
	return out
}

// Overview handles GET /api/v1/attack-surface/discovery
// @Summary      Discovery stages
// @Description  The organization's coverage work in four stages (asset discovery, exposure scan, validation and
// @Description  scoping, technology discovery): per stage its status, last run, progress and capabilities, the daily
// @Description  budget and the last automatic attribution pass. Needs access to all of the organization's assets.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DiscoveryOverviewResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/discovery [get]
func (h *EASMDiscoveryHandler) Overview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.authorize(w, r)
	if !ok {
		return
	}
	o, err := h.svc.Overview(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("discovery: overview", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the discovery stages").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toDiscoveryOverview(o))
}

// Export handles GET /api/v1/attack-surface/discovery/export
// @Summary      Export the discovery stages
// @Description  The discovery stages as CSV, one row per stage and capability, with the same figures as the view.
// @Tags         Attack Surface
// @Produce      text/csv
// @Security     BearerAuth
// @Success      200  {string}  string
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/discovery/export [get]
func (h *EASMDiscoveryHandler) Export(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.authorize(w, r)
	if !ok {
		return
	}
	o, err := h.svc.Overview(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("discovery: export", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to export the discovery stages").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="discovery-stages.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"stage", "stage_status", "stage_reason", "capability", "pairs", "covered", "due_now", "queued",
		"failed", "blocked", "paused", "paused_reason", "last_attempt_at", "last_success_at", "last_run_status",
		"last_run_started_at", "last_run_completed_at"})
	for _, row := range discoveryCSVRows(o) {
		_ = cw.Write(sanitizeCSVRow(row))
	}
	cw.Flush()
}

func csvTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// discoveryCSVRows are the export rows: one per stage and capability.
func discoveryCSVRows(o *coverageapp.Overview) [][]string {
	var out [][]string
	for _, s := range o.Stages {
		for _, c := range s.Capabilities {
			var status string
			var started, completed *time.Time
			if c.LastRun != nil {
				status, started, completed = c.LastRun.Status, c.LastRun.StartedAt, c.LastRun.CompletedAt
			}
			out = append(out, []string{string(s.Stage), string(s.Status), s.Reason, c.Capability,
				strconv.Itoa(c.Pairs), strconv.Itoa(c.Covered), strconv.Itoa(c.DueNow), strconv.Itoa(c.Queued),
				strconv.Itoa(c.Failed), strconv.Itoa(c.Blocked), strconv.Itoa(c.Paused), c.PausedReason,
				csvTime(c.LastAttemptAt), csvTime(c.LastSuccessAt), status, csvTime(started), csvTime(completed)})
		}
	}
	return out
}

// RunStage handles POST /api/v1/attack-surface/discovery/stages/{stage}/run
// @Summary      Run a discovery stage
// @Description  Makes the stage's covered, due and failed coverage pairs due now; the coverage loop plans them on its
// @Description  next pass through the dispatch gate (scope, tiers, exclusions, windows), within the daily budget.
// @Description  Paused, blocked and queued pairs are left alone. At most once a minute per stage (429 with
// @Description  Retry-After); refused while automatic coverage is off or the daily budget is spent (409).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        stage  path  string  true  "Stage"  Enums(asset_discovery, exposure_scan, validation_scoping, technology_discovery)
// @Success      202  {object}  DiscoveryRunNowResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /attack-surface/discovery/stages/{stage}/run [post]
func (h *EASMDiscoveryHandler) RunStage(w http.ResponseWriter, r *http.Request) {
	stage := covdom.DiscoveryStage(chi.URLParam(r, "stage"))
	if !stage.Valid() {
		apierror.BadRequest("Unknown discovery stage").WriteJSON(w)
		return
	}
	h.run(w, r, []covdom.DiscoveryStage{stage}, false)
}

// RunAll handles POST /api/v1/attack-surface/discovery/run
// @Summary      Run every discovery stage
// @Description  Run for every stage at once; a stage run less than a minute ago is skipped (listed in skipped), and
// @Description  when every stage is, the call is refused (429 with Retry-After).
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      202  {object}  DiscoveryRunNowResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /attack-surface/discovery/run [post]
func (h *EASMDiscoveryHandler) RunAll(w http.ResponseWriter, r *http.Request) {
	h.run(w, r, covdom.DiscoveryStages(), true)
}

func (h *EASMDiscoveryHandler) run(w http.ResponseWriter, r *http.Request, stages []covdom.DiscoveryStage, all bool) {
	tenantID, ok := h.authorize(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Run(r.Context(), tenantID, stages)
	if err != nil {
		h.writeRunErr(w, err)
		return
	}
	resp := DiscoveryRunNowResponse{Started: stageNames(res.Started), Skipped: stageNames(res.Skipped),
		Capabilities: res.Capabilities, PairsMadeDue: res.PairsMadeDue, NextPassWithin: int(res.NextPassWithin.Seconds())}
	if resp.Capabilities == nil {
		resp.Capabilities = []string{}
	}
	if h.audit != nil {
		auditapp.RecordOrWarn(r.Context(), h.logger, h.audit, h.actx(r),
			auditapp.NewSuccessEvent(auditdom.ActionEASMDiscoveryRun, auditdom.ResourceTypeTenant, tenantID.String()).
				WithMessage("Discovery stages run by hand").
				WithMetadata("all", all).
				WithMetadata("stages", resp.Started).
				WithMetadata("skipped", resp.Skipped).
				WithMetadata("pairs_made_due", res.PairsMadeDue))
	}
	writeJSON(w, http.StatusAccepted, resp)
}

func stageNames(in []covdom.DiscoveryStage) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	return out
}

func (h *EASMDiscoveryHandler) writeRunErr(w http.ResponseWriter, err error) {
	var soon *coverageapp.TooSoonError
	switch {
	case errors.As(err, &soon):
		secs := int(time.Until(soon.Until).Seconds()) + 1
		if secs < 1 || soon.Until.IsZero() {
			secs = int(coverageapp.RunNowInterval.Seconds())
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		apierror.FromCode(apierror.CodeDiscoveryRunTooSoon).WriteJSON(w)
	case errors.Is(err, coverageapp.ErrLoopOff):
		apierror.FromCode(apierror.CodeDiscoveryLoopOff).WriteJSON(w)
	case errors.Is(err, coverageapp.ErrCoverageOff):
		apierror.FromCode(apierror.CodeDiscoveryCoverageOff).WriteJSON(w)
	case errors.Is(err, coverageapp.ErrBudgetSpent):
		apierror.FromCode(apierror.CodeDiscoveryBudgetSpent).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Unknown discovery stage").WriteJSON(w)
	default:
		h.logger.Error("discovery: run", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to run the discovery stage").WriteJSON(w)
	}
}

// AbortAll handles POST /api/v1/attack-surface/discovery/cancel
// @Summary      Abort every discovery run
// @Description  Cancels the organization's active coverage runs (never a person's scan) through the run cancel: the
// @Description  sensors are told to stop and the coverage loop settles the canceled pairs on its next pass. Automatic
// @Description  coverage keeps its schedule.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DiscoveryAbortResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/discovery/cancel [post]
func (h *EASMDiscoveryHandler) AbortAll(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.authorize(w, r)
	if !ok {
		return
	}
	res, err := h.svc.AbortAll(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("discovery: abort all", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to abort the discovery runs").WriteJSON(w)
		return
	}
	if h.audit != nil {
		auditapp.RecordOrWarn(r.Context(), h.logger, h.audit, h.actx(r),
			auditapp.NewSuccessEvent(auditdom.ActionEASMDiscoveryAborted, auditdom.ResourceTypeTenant, tenantID.String()).
				WithMessage("Discovery runs aborted").
				WithMetadata("canceled", res.Canceled).
				WithMetadata("failed", res.Failed))
	}
	writeJSON(w, http.StatusOK, DiscoveryAbortResponse{Canceled: res.Canceled, Failed: res.Failed})
}
