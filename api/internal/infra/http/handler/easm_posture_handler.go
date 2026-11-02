package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	postureapp "github.com/openctemio/openctem/api/internal/app/posture"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/posture"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
)

// EASMPostureHandler serves the attack surface posture score
// (docs/architecture/easm-posture.md).
type EASMPostureHandler struct {
	svc    *postureapp.Service
	audit  auditapp.EventWriter
	logger *logger.Logger
}

// NewEASMPostureHandler creates the handler. audit may be nil (tests).
func NewEASMPostureHandler(svc *postureapp.Service, audit auditapp.EventWriter, log *logger.Logger) *EASMPostureHandler {
	return &EASMPostureHandler{svc: svc, audit: audit, logger: log}
}

// PostureStateResponse is the freshness of the stored facts.
type PostureStateResponse struct {
	RefreshEvery  string     `json:"refresh_every" enums:"manual,1h,6h,24h"`
	ComputedAt    *time.Time `json:"computed_at,omitempty"`
	NextRefreshAt *time.Time `json:"next_refresh_at,omitempty"`
	// Building is true until the first computation is stored.
	Building  bool   `json:"building"`
	LastError string `json:"last_error,omitempty"`
	// Stale: the last refresh failed, or the facts are older than twice
	// the schedule.
	Stale bool `json:"stale"`
}

// PostureCategoryResponse is one category's part of a score.
type PostureCategoryResponse struct {
	Category  string  `json:"category" enums:"vulnerabilities,hijackable_subdomains,exposed_services,cloud_storage,misconfiguration,suspicious_activity"`
	Max       float64 `json:"max"`
	Points    float64 `json:"points"`
	Issues    int64   `json:"issues"`
	Deduction float64 `json:"deduction"`
	// ScoreIfFixed and GradeIfFixed: the score once every issue of the
	// category is fixed (absent without issues).
	ScoreIfFixed *int   `json:"score_if_fixed,omitempty"`
	GradeIfFixed string `json:"grade_if_fixed,omitempty"`
}

// PostureScoreResponse is a score.
type PostureScoreResponse struct {
	// Measured is false when no surface asset is in the read: no grade.
	Measured   bool                      `json:"measured"`
	Score      int                       `json:"score"`
	Grade      string                    `json:"grade,omitempty" enums:"A,B,C,D,F"`
	Assets     int64                     `json:"assets"`
	Categories []PostureCategoryResponse `json:"categories"`
}

// PosturePlanStepResponse is one step of the fix plan.
type PosturePlanStepResponse struct {
	// AssetID is empty for issues without an asset.
	AssetID    string  `json:"asset_id,omitempty"`
	AssetName  string  `json:"asset_name,omitempty"`
	Category   string  `json:"category"`
	Points     float64 `json:"points"`
	Issues     int64   `json:"issues"`
	ScoreAfter int     `json:"score_after"`
	GradeAfter string  `json:"grade_after"`
}

// PosturePlanResponse is what to fix to reach the next grade.
type PosturePlanResponse struct {
	Target  string                    `json:"target,omitempty"`
	Floor   int                       `json:"floor,omitempty"`
	Reached bool                      `json:"reached"`
	Steps   []PosturePlanStepResponse `json:"steps"`
}

// PostureReductionResponse is the risk reduction of one asset criticality.
type PostureReductionResponse struct {
	Criticality string  `json:"criticality" enums:"critical,high,medium,low"`
	Assets      int64   `json:"assets"`
	Issues      int64   `json:"issues"`
	Points      float64 `json:"points"`
	Share       float64 `json:"share"`
	Gain        float64 `json:"gain"`
}

// PostureRootResponse is one root domain's score.
type PostureRootResponse struct {
	RootDomain  string `json:"root_domain"`
	Score       int    `json:"score"`
	Grade       string `json:"grade,omitempty"`
	Assets      int64  `json:"assets"`
	Issues      int64  `json:"issues"`
	TopCategory string `json:"top_category,omitempty"`
}

// PostureResponse is the posture of the caller's read.
type PostureResponse struct {
	State PostureStateResponse `json:"state"`
	// Scoped: the figures cover only the caller's data scope.
	Scoped bool `json:"scoped"`
	// Filtered: the read named root domains or other filters.
	Filtered bool                 `json:"filtered"`
	Score    PostureScoreResponse `json:"score"`
	// PreviousScore and PreviousGrade are the organization-wide result
	// before the last change; only for an unscoped, unfiltered read.
	PreviousScore *int                       `json:"previous_score,omitempty"`
	PreviousGrade string                     `json:"previous_grade,omitempty"`
	Plan          PosturePlanResponse        `json:"plan"`
	Reductions    []PostureReductionResponse `json:"reductions"`
	Roots         []PostureRootResponse      `json:"roots"`
	RootsTotal    int                        `json:"roots_total"`
}

// PostureScheduleRequest changes the refresh schedule.
type PostureScheduleRequest struct {
	RefreshEvery string `json:"refresh_every" enums:"manual,1h,6h,24h"`
}

func toPostureState(st *posture.State, now time.Time) PostureStateResponse {
	out := PostureStateResponse{RefreshEvery: string(st.RefreshEvery), ComputedAt: st.ComputedAt,
		NextRefreshAt: st.NextRefreshAt, Building: st.ComputedAt == nil, LastError: st.LastError}
	out.Stale = st.LastError != ""
	if st.ComputedAt != nil {
		var every time.Duration
		switch st.RefreshEvery {
		case posture.ScheduleHourly:
			every = time.Hour
		case posture.Schedule6h:
			every = 6 * time.Hour
		case posture.ScheduleDaily:
			every = 24 * time.Hour
		}
		if every > 0 && now.Sub(*st.ComputedAt) > 2*every {
			out.Stale = true
		}
	}
	return out
}

func toPostureScore(sc posture.Score, gains []posture.CategoryGain) PostureScoreResponse {
	byCat := map[posture.Category]posture.CategoryGain{}
	for _, g := range gains {
		byCat[g.Category] = g
	}
	out := PostureScoreResponse{Measured: sc.Measured, Score: sc.Value, Grade: sc.Grade, Assets: sc.Assets,
		Categories: make([]PostureCategoryResponse, 0, len(sc.Categories))}
	for _, c := range sc.Categories {
		row := PostureCategoryResponse{Category: string(c.Category), Max: c.Max, Points: c.Points, Issues: c.Issues, Deduction: c.Deduction}
		if g, ok := byCat[c.Category]; ok && sc.Measured {
			v := g.ScoreAfter
			row.ScoreIfFixed, row.GradeIfFixed = &v, g.GradeAfter
		}
		out.Categories = append(out.Categories, row)
	}
	return out
}

// ToPostureResponse renders a view (shared with the dashboard widget).
func ToPostureResponse(v *postureapp.View, now time.Time) PostureResponse {
	out := PostureResponse{State: toPostureState(v.State, now), Scoped: v.Scoped, Filtered: v.Filtered,
		Score:      toPostureScore(v.Score, v.Gains),
		Plan:       PosturePlanResponse{Target: v.Plan.Target, Floor: v.Plan.Floor, Reached: v.Plan.Reached, Steps: []PosturePlanStepResponse{}},
		Reductions: make([]PostureReductionResponse, 0, len(v.Reductions)),
		Roots:      make([]PostureRootResponse, 0, len(v.Roots)), RootsTotal: v.RootsTotal}
	if !v.Scoped && !v.Filtered {
		out.PreviousScore, out.PreviousGrade = v.State.PreviousScore, v.State.PreviousGrade
	}
	for _, s := range v.Plan.Steps {
		step := PosturePlanStepResponse{AssetName: s.Item.Name, Category: string(s.Item.Category), Points: s.Item.Points,
			Issues: s.Item.Issues, ScoreAfter: s.ScoreAfter, GradeAfter: s.GradeAfter}
		if s.Item.AssetID != posture.NoAsset.String() {
			step.AssetID = s.Item.AssetID
		}
		out.Plan.Steps = append(out.Plan.Steps, step)
	}
	for _, r := range v.Reductions {
		out.Reductions = append(out.Reductions, PostureReductionResponse(r))
	}
	for _, r := range v.Roots {
		out.Roots = append(out.Roots, PostureRootResponse{RootDomain: r.RootDomain, Score: r.Score.Value, Grade: r.Score.Grade,
			Assets: r.Score.Assets, Issues: r.Issues, TopCategory: string(r.Top)})
	}
	return out
}

func postureCaller(r *http.Request) postureapp.Caller {
	ctx := r.Context()
	return postureapp.Caller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.ReadsOnOwnScope(ctx),
	}
}

func (h *EASMPostureHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant").WriteJSON(w)
		return id, false
	}
	return id, true
}

func (h *EASMPostureHandler) record(r *http.Request, tenantID shared.ID, action auditdom.Action, msg string, meta map[string]any) {
	if h.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeTenant, tenantID.String()).WithMessage(msg)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	ctx := r.Context()
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx)}
	auditapp.RecordOrWarn(r.Context(), h.logger, h.audit, actx, ev)
}

// Get handles GET /api/v1/attack-surface/posture
// @Summary      Attack surface posture
// @Description  The posture score (A to F) of the external attack surface the caller may see, with each category's
// @Description  contribution, what to fix to reach the next grade, the risk reduction by asset criticality and the
// @Description  score of each root domain. Read from facts precomputed on the organization's schedule.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: attack_surface_posture GET /attack-surface/posture
// @Param  root_domain  query  []string  false  "root domain: any of (comma list)"  collectionFormat(csv)
// @Param  root_domain_contains  query  string  false  "root domain contains"
// @Param  root_domain_not  query  []string  false  "root domain: none of (comma list)"  collectionFormat(csv)
// @Param  criticality  query  []string  false  "criticality: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  criticality_not  query  []string  false  "criticality: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// end filterspec-params
// @Success      200  {object}  PostureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/posture [get]
func (h *EASMPostureHandler) Get(w http.ResponseWriter, r *http.Request) {
	spec, ok := filterquery.Route{Name: "GET /attack-surface/posture", Registry: posture.Fields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}.ParseQuery(w, r)
	if !ok {
		return
	}
	v, err := h.svc.Read(r.Context(), postureCaller(r), spec)
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.logger.Error("posture read", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the posture").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ToPostureResponse(v, time.Now()))
}

// Recalculate handles POST /api/v1/attack-surface/posture/refresh
// @Summary      Recalculate the posture now
// @Description  Rebuilds the organization's posture facts now. At most once every five minutes per organization (429
// @Description  with Retry-After); 409 while a refresh runs.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PostureStateResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /attack-surface/posture/refresh [post]
func (h *EASMPostureHandler) Recalculate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	st, wait, err := h.svc.Recalculate(r.Context(), tenantID)
	switch {
	case errors.Is(err, postureapp.ErrTooSoon):
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		apierror.TooManyRequests("The posture was recalculated less than five minutes ago; try again later").WriteJSON(w)
		return
	case errors.Is(err, posture.ErrBusy):
		apierror.Conflict("The posture is being recalculated").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("posture recalculate", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to recalculate the posture").WriteJSON(w)
		return
	}
	h.record(r, tenantID, auditdom.ActionEASMPostureRecalculated, "Attack surface posture recalculated", nil)
	writeJSON(w, http.StatusOK, toPostureState(st, time.Now()))
}

// SetSchedule handles PUT /api/v1/attack-surface/posture/schedule
// @Summary      Set the posture refresh schedule
// @Description  How often the organization's posture is recomputed: manual, 1h, 6h or 24h.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  PostureScheduleRequest  true  "Schedule"
// @Success      200  {object}  PostureStateResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/posture/schedule [put]
func (h *EASMPostureHandler) SetSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req PostureScheduleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	sched := posture.Schedule(req.RefreshEvery)
	if !sched.Valid() {
		apierror.BadRequest("refresh_every must be one of manual, 1h, 6h, 24h").WriteJSON(w)
		return
	}
	st, err := h.svc.ChangeSchedule(r.Context(), tenantID, sched)
	if err != nil {
		h.logger.Error("posture schedule", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to change the schedule").WriteJSON(w)
		return
	}
	h.record(r, tenantID, auditdom.ActionEASMPostureScheduleChanged, "Attack surface posture schedule changed",
		map[string]any{"refresh_every": string(sched)})
	writeJSON(w, http.StatusOK, toPostureState(st, time.Now()))
}
