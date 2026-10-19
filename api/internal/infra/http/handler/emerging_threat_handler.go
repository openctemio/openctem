package handler

// Emerging-threat alerts (docs/rfcs/RFC-117-emerging-threat-alerts.md §4).
// The organization comes from the token; every read and write is narrowed
// to the caller's data scope: an alert with no asset in scope answers 404,
// and its counts, assets and findings are those in scope. Marking an alert
// not affected needs every asset of it in scope (409 otherwise).

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	threatalertapp "github.com/openctemio/openctem/api/internal/app/threatalert"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EmergingThreatHandler serves /api/v1/emerging-threats.
type EmergingThreatHandler struct {
	service   *threatalertapp.Service
	dataScope DataScopeEnforcer
	logger    *logger.Logger
}

// NewEmergingThreatHandler creates the handler. A nil data scope enforcer
// is refused at request time (fail closed).
func NewEmergingThreatHandler(svc *threatalertapp.Service, scope DataScopeEnforcer, log *logger.Logger) *EmergingThreatHandler {
	return &EmergingThreatHandler{service: svc, dataScope: scope, logger: log}
}

// EmergingThreatSummary is one alert in the list.
type EmergingThreatSummary struct {
	ID                   string     `json:"id"`
	VulnID               string     `json:"vuln_id"`
	Title                string     `json:"title"`
	Severity             string     `json:"severity"`
	Level                string     `json:"level" enums:"immediate,digest,listed"`
	Tier                 string     `json:"tier" enums:"confirmed,possible"`
	State                string     `json:"state" enums:"new,acknowledged,remediating,not_affected,resolved"`
	ETS                  int        `json:"ets"`
	InKEV                bool       `json:"in_kev"`
	KEVRansomware        bool       `json:"kev_ransomware"`
	EPSS                 *float64   `json:"epss"`
	ConfirmedAssets      int        `json:"confirmed_assets"`
	PossibleAssets       int        `json:"possible_assets"`
	InternetFacingAssets int        `json:"internet_facing_assets"`
	LastEventKind        string     `json:"last_event_kind"`
	EventAt              *time.Time `json:"event_at"`
	SourceAt             *time.Time `json:"source_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// EmergingThreatListResponse is a page of alerts and the viewer's counts.
type EmergingThreatListResponse struct {
	ListResponse[EmergingThreatSummary]
	Summary threatalert.Summary `json:"summary"`
}

// EmergingThreatAsset is one affected asset in scope.
type EmergingThreatAsset struct {
	AssetID        string `json:"asset_id"`
	AssetName      string `json:"asset_name"`
	AssetType      string `json:"asset_type"`
	Tier           string `json:"tier" enums:"confirmed,likely,possible"`
	Confidence     int    `json:"confidence"`
	InternetFacing bool   `json:"internet_facing"`
	Criticality    string `json:"criticality"`
	Product        string `json:"product"`
	VersionSeen    string `json:"version_seen"`
	FindingID      string `json:"finding_id"`
	FindingStatus  string `json:"finding_status"`
	TaskID         string `json:"task_id"`
}

// EmergingThreatEvent is one public event of the vulnerability.
type EmergingThreatEvent struct {
	Kind     string         `json:"kind"`
	At       time.Time      `json:"at"`
	SourceAt *time.Time     `json:"source_at"`
	Detail   map[string]any `json:"detail"`
}

// EmergingThreatDetail is one alert as the viewer sees it.
type EmergingThreatDetail struct {
	EmergingThreatSummary
	ETSBreakdown      threatalert.Breakdown `json:"ets_breakdown"`
	RecommendedAction string                `json:"recommended_action" enums:"patch_now,confirm,patch_within_sla"`
	Description       string                `json:"description"`
	CVSSScore         *float64              `json:"cvss_score"`
	PublishedAt       *time.Time            `json:"published_at"`
	KEVDateAdded      string                `json:"kev_date_added"`
	StateReason       string                `json:"state_reason"`
	StateNote         string                `json:"state_note"`
	StateChangedAt    *time.Time            `json:"state_changed_at"`
	SuppressedUntil   *time.Time            `json:"suppressed_until"`
	CanSuppress       bool                  `json:"can_suppress"`
	Assets            []EmergingThreatAsset `json:"assets"`
	Timeline          []EmergingThreatEvent `json:"timeline"`
}

// EmergingThreatStateRequest is a triage decision.
type EmergingThreatStateRequest struct {
	State  string `json:"state" enums:"new,acknowledged,remediating,not_affected"`
	Reason string `json:"reason" enums:"version_not_affected,feature_not_used,compensating_control,wrong_product,asset_decommissioned"`
	Note   string `json:"note"`
}

func toEmergingSummary(a *threatalert.Alert) EmergingThreatSummary {
	return EmergingThreatSummary{ID: a.ID.String(), VulnID: a.VulnID, Title: a.Title, Severity: a.Severity,
		Level: string(a.Level), Tier: string(a.Tier), State: string(a.State), ETS: a.ETS, InKEV: a.InKEV,
		KEVRansomware: a.KEVRansomware, EPSS: a.EPSS, ConfirmedAssets: a.Confirmed, PossibleAssets: a.Possible,
		InternetFacingAssets: a.InternetFacing, LastEventKind: a.LastEventKind, EventAt: a.EventAt, SourceAt: a.SourceAt,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}

func toEmergingDetail(d *threatalert.Detail) EmergingThreatDetail {
	out := EmergingThreatDetail{EmergingThreatSummary: toEmergingSummary(&d.Alert), ETSBreakdown: d.Alert.Breakdown,
		RecommendedAction: threatalert.RecommendedAction(d.Alert.Tier, d.Alert.Breakdown),
		Description:       threatalert.PlainText(d.Vuln.Description, 1000), CVSSScore: d.Vuln.CVSSScore,
		PublishedAt: d.Vuln.Published, StateReason: d.Alert.StateReason, StateNote: d.Alert.StateNote,
		StateChangedAt: d.Alert.StateChangedAt, SuppressedUntil: d.Alert.SuppressedUntil, CanSuppress: d.AllInScope,
		Assets: make([]EmergingThreatAsset, 0, len(d.Assets)), Timeline: make([]EmergingThreatEvent, 0, len(d.Timeline))}
	if d.Vuln.KEVDateAdded != nil {
		out.KEVDateAdded = d.Vuln.KEVDateAdded.Format(time.DateOnly)
	}
	for _, a := range d.Assets {
		v := EmergingThreatAsset{AssetID: a.AssetID.String(), AssetName: a.Name, AssetType: a.Type, Tier: string(a.Kind),
			Confidence: a.Confidence, InternetFacing: a.InternetFacing, Criticality: a.Criticality, Product: a.Product,
			VersionSeen: a.Version, FindingStatus: a.FindingStatus}
		if a.FindingID != nil {
			v.FindingID = a.FindingID.String()
		}
		if a.TaskID != nil {
			v.TaskID = a.TaskID.String()
		}
		out.Assets = append(out.Assets, v)
	}
	for _, e := range d.Timeline {
		det := e.Detail
		if det == nil {
			det = map[string]any{}
		}
		out.Timeline = append(out.Timeline, EmergingThreatEvent{Kind: e.Kind, At: e.At, SourceAt: e.SourceAt, Detail: det})
	}
	return out
}

func (h *EmergingThreatHandler) scope(w http.ResponseWriter, r *http.Request) (shared.ID, *shared.DataScope, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return shared.ID{}, nil, false
	}
	if h.service == nil || h.dataScope == nil {
		apierror.NotFound("Emerging threats").WriteJSON(w)
		return shared.ID{}, nil, false
	}
	scope, err := h.dataScope.Resolve(r.Context(), tid)
	if err != nil {
		h.logger.Warn("emerging threats: resolve data scope", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Failed to resolve data scope").WriteJSON(w)
		return shared.ID{}, nil, false
	}
	return tid, scope, true
}

func (h *EmergingThreatHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, threatalert.ErrOutOfScope):
		apierror.Conflict("The alert has assets outside your data scope: it cannot be marked not affected").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Emerging threat").WriteJSON(w)
	default:
		h.logger.Error("emerging threats", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Emerging threats failed").WriteJSON(w)
	}
}

// List handles GET /api/v1/emerging-threats.
// @Summary      List emerging-threat alerts
// @Description  One alert per vulnerability that newly affects the organization (new CVE, KEV addition, EPSS jump), with the Emerging Threat Score and the level that decided delivery. Only alerts with at least one asset in the caller's data scope; counts are those in scope. state=open (default) is new, acknowledged and remediating; state=all lists every state.
// @Tags         Emerging threats
// @Produce      json
// @Security     BearerAuth
// @Param        level     query string false "immediate, digest or listed"
// @Param        state     query string false "open (default), all, new, acknowledged, remediating, not_affected or resolved"
// @Param        tier      query string false "confirmed or possible"
// @Param        exposure  query string false "internet: only alerts with an internet-facing asset"
// @Param        search    query string false "Vulnerability id or title"
// @Param        page      query int false "Page (default 1)"
// @Param        per_page  query int false "Per page (default 25, max 100)"
// @Success      200  {object}  EmergingThreatListResponse
// @Failure      400  {object}  apierror.Error
// @Router       /emerging-threats [get]
func (h *EmergingThreatHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, scope, ok := h.scope(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := threatalert.ListFilter{Level: threatalert.Level(q.Get("level")), Tier: threatalert.Tier(q.Get("tier")),
		InternetOnly: q.Get("exposure") == "internet", Search: truncateQuery(q.Get("search"), 100)}
	if f.Level != "" && !f.Level.IsValid() {
		apierror.BadRequest("level must be immediate, digest or listed").WriteJSON(w)
		return
	}
	if f.Tier != "" && !f.Tier.IsValid() {
		apierror.BadRequest("tier must be confirmed or possible").WriteJSON(w)
		return
	}
	switch st := q.Get("state"); st {
	case "", "open":
		f.States = []threatalert.State{threatalert.StateNew, threatalert.StateAcknowledged, threatalert.StateRemediating}
	case sectionAll:
	default:
		if !threatalert.State(st).IsValid() {
			apierror.BadRequest("state must be open, all, new, acknowledged, remediating, not_affected or resolved").WriteJSON(w)
			return
		}
		f.States = []threatalert.State{threatalert.State(st)}
	}
	paging, ok := listPageMax(w, r, 25, 100)
	if !ok {
		return
	}
	f.Page, f.PerPage = paging.Page, paging.PerPage
	items, total, sum, err := h.service.List(r.Context(), tid, scope, f)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]EmergingThreatSummary, 0, len(items))
	for i := range items {
		data = append(data, toEmergingSummary(&items[i]))
	}
	pages := (total + f.PerPage - 1) / f.PerPage
	writeJSON(w, http.StatusOK, EmergingThreatListResponse{ListResponse: ListResponse[EmergingThreatSummary]{Data: data,
		Total: int64(total), Page: f.Page, PerPage: f.PerPage, TotalPages: pages,
		Links: NewPaginationLinks(r, f.Page, f.PerPage, pages)}, Summary: sum})
}

// Get handles GET /api/v1/emerging-threats/{id}.
// @Summary      Get an emerging-threat alert
// @Description  The alert with its score breakdown, what changed (public events), exploitation facts and the affected assets in the caller's data scope (confirmed, likely, possibly affected) with their findings and remediation tasks. can_suppress says whether every asset of the alert is in scope. 404 when no asset of the alert is in scope.
// @Tags         Emerging threats
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Alert ID"
// @Success      200  {object}  EmergingThreatDetail
// @Failure      404  {object}  apierror.Error
// @Router       /emerging-threats/{id} [get]
func (h *EmergingThreatHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, scope, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Emerging threat").WriteJSON(w)
		return
	}
	d, err := h.service.Get(r.Context(), tid, scope, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEmergingDetail(d))
}

// SetState handles POST /api/v1/emerging-threats/{id}/state.
// @Summary      Triage an emerging-threat alert
// @Description  Sets the alert's state: new (reopen), acknowledged, remediating or not_affected. not_affected needs a reason (version_not_affected, feature_not_used, compensating_control, wrong_product, asset_decommissioned) and every asset of the alert in the caller's data scope; it suppresses the alert for 180 days unless a stronger match or a KEV addition reopens it. Audited.
// @Tags         Emerging threats
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path string true "Alert ID"
// @Param        body  body EmergingThreatStateRequest true "Decision"
// @Success      200  {object}  EmergingThreatDetail
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /emerging-threats/{id}/state [post]
func (h *EmergingThreatHandler) SetState(w http.ResponseWriter, r *http.Request) {
	tid, scope, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Emerging threat").WriteJSON(w)
		return
	}
	actor, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req EmergingThreatStateRequest
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	d, err := h.service.ChangeState(r.Context(), tid, scope, id, threatalertapp.StateChange{
		State: threatalert.State(req.State), Reason: req.Reason, Note: strings.TrimSpace(req.Note), Actor: actor,
	}, audit.AuditContext{
		TenantID: tid.String(), ActorID: actor.String(), ActorEmail: auditActorEmail(r.Context()),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEmergingDetail(d))
}
