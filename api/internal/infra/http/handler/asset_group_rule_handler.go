package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type assetgroupPage = pagination.Result[*assetgroup.HistoryEntry]

// Asset groups that fill themselves: the rule, the preview, pasted lists,
// "add all matching" and the membership history.

// maxRuleBody bounds a rule or paste request body.
const maxRuleBody = 2 << 20

// GroupRuleResponse is a group's rule and how its last evaluation went.
type GroupRuleResponse struct {
	// Document is the rule: {"v":1,"filter":{...},"domains":[...],"covered_by":[...],"include_related":false}.
	Document *assetgroup.Rule `json:"document"`
	// Status: ok, idle (not evaluated yet), paused (the editor left: members
	// stay as they were) or over_cap (the rule matches more than the cap:
	// members stay as they were).
	Status      string     `json:"status" enums:"idle,ok,paused,over_cap"`
	EvaluatedAt *time.Time `json:"evaluated_at,omitempty"`
	// Excluded counts the assets taken out by hand; the rule never brings
	// them back.
	Excluded int `json:"excluded"`
	Cap      int `json:"cap"`
}

func toGroupRuleResponse(st *assetgroup.RuleState) *GroupRuleResponse {
	if st == nil || st.Rule == nil {
		return nil
	}
	return &GroupRuleResponse{Document: st.Rule, Status: st.Status, EvaluatedAt: st.EvaluatedAt,
		Excluded: st.Excluded, Cap: assetgroup.DefaultMemberCap}
}

// groupResponse is toAssetGroupResponse plus the group's rule.
func (h *AssetGroupHandler) groupResponse(r *http.Request, g *assetgroup.AssetGroup) AssetGroupResponse {
	resp := toAssetGroupResponse(g)
	if st, err := h.service.GetGroupRule(r.Context(), middleware.MustGetTenantID(r.Context()), g.ID()); err == nil {
		resp.Rule = toGroupRuleResponse(st)
	}
	return resp
}

// RuleImpactResponse is what a change means for the teams and scans that use
// the group.
type RuleImpactResponse = asset.RuleImpact

// PreviewGroupRuleRequest asks what a rule would match.
type PreviewGroupRuleRequest struct {
	// Rule is the rule document.
	Rule json.RawMessage `json:"rule" swaggertype:"object"`
	// GroupID, for a group being edited, adds who would join and leave and
	// what depends on the group.
	GroupID string `json:"group_id,omitempty" validate:"omitempty,uuid"`
}

// SetGroupRuleRequest sets or clears a group's rule.
type SetGroupRuleRequest struct {
	// Rule is the rule document; null removes the rule (its members stay as
	// plain members).
	Rule json.RawMessage `json:"rule" swaggertype:"object"`
}

// SetGroupRuleResponse is the group's rule after the change.
type SetGroupRuleResponse struct {
	Rule   *GroupRuleResponse `json:"rule,omitempty"`
	Joined int                `json:"joined"`
	Left   int                `json:"left"`
	Impact RuleImpactResponse `json:"impact"`
}

func decodeRuleBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func writeRuleJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// PreviewRule handles POST /api/v1/asset-groups/rule/preview
// @Summary      Preview a group rule
// @Description  Evaluates a rule as the caller, inside the caller's data scope, without saving: the number of matches, the first 20 and, for an existing group, how many assets would join and leave and which teams and scans use the group.
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        body  body      PreviewGroupRuleRequest  true  "Rule"
// @Success      200   {object}  asset.RulePreview
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/rule/preview [post]
func (h *AssetGroupHandler) PreviewRule(w http.ResponseWriter, r *http.Request) {
	var req PreviewGroupRuleRequest
	if !decodeRuleBody(w, r, &req) {
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	var gid *shared.ID
	if req.GroupID != "" {
		id, err := shared.IDFromString(req.GroupID)
		if err != nil {
			apierror.BadRequest("Invalid group ID").WriteJSON(w)
			return
		}
		gid = &id
	}
	p, err := h.service.PreviewGroupRule(r.Context(), middleware.MustGetTenantID(r.Context()), gid, req.Rule)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeRuleJSON(w, http.StatusOK, p)
}

// GetRule handles GET /api/v1/asset-groups/{id}/rule
// @Summary      Get a group's rule
// @Description  The rule of a group that fills itself, its status and the number of assets taken out by hand. 404 when the group has no rule.
// @Tags         Asset Groups
// @Produce      json
// @Param        id   path      string  true  "Asset Group ID"
// @Success      200  {object}  GroupRuleResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/rule [get]
func (h *AssetGroupHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}
	st, err := h.service.GetGroupRule(r.Context(), middleware.MustGetTenantID(r.Context()), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := toGroupRuleResponse(st)
	if resp == nil {
		apierror.NotFound("Group rule").WriteJSON(w)
		return
	}
	writeRuleJSON(w, http.StatusOK, resp)
}

// SetRule handles PUT /api/v1/asset-groups/{id}/rule
// @Summary      Set a group's rule
// @Description  Makes the group fill itself with the assets the rule matches inside the caller's data scope, plus the assets added by hand, minus the assets taken out by hand; the rule is evaluated at once and again when assets change. A change that brings assets into a group that team scope rules or scans use is audited and answered with an impact summary. A group used by a team that holds a privileged role is changed only by the owner after a recent sign-in. A null rule removes the rule.
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string                true  "Asset Group ID"
// @Param        body  body      SetGroupRuleRequest   true  "Rule"
// @Success      200   {object}  SetGroupRuleResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/rule [put]
func (h *AssetGroupHandler) SetRule(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}
	var req SetGroupRuleRequest
	if !decodeRuleBody(w, r, &req) {
		return
	}
	// A body without the key must not clear the rule: null says so.
	if len(req.Rule) == 0 {
		apierror.BadRequest("rule is required: send the rule document, or null to remove the rule").WriteJSON(w)
		return
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	ch, err := h.service.ChangeGroupRule(r.Context(), tenantID, id, req.Rule)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditRuleChange(r, id, ch)
	writeRuleJSON(w, http.StatusOK, SetGroupRuleResponse{
		Rule: toGroupRuleResponse(ch.State), Joined: ch.Result.Joined, Left: ch.Result.Left, Impact: ch.Impact})
}

func (h *AssetGroupHandler) auditContext(r *http.Request) auditapp.AuditContext {
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
	}
}

// auditRuleChange records a rule change; one that widens a group that teams
// or scans use is recorded as such, with who depends on it.
func (h *AssetGroupHandler) auditRuleChange(r *http.Request, id shared.ID, ch *asset.RuleChange) {
	if h.auditService == nil {
		return
	}
	action, sev, msg := auditdom.ActionAssetGroupRuleChanged, auditdom.SeverityMedium, "The rule of an asset group was changed"
	if ch.Impact.Widens {
		action, sev, msg = auditdom.ActionAssetGroupRuleWidened, auditdom.SeverityHigh,
			"The rule of an asset group that teams or scans use now brings in more assets"
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeAssetGroup, id.String()).
		WithMessage(msg).WithSeverity(sev).
		WithMetadata("joined", ch.Result.Joined).WithMetadata("left", ch.Result.Left).
		WithMetadata("teams", len(ch.Impact.Teams)).WithMetadata("scans", len(ch.Impact.Scans)).
		WithMetadata("privileged_team", ch.Impact.Privilege)
	if err := h.auditService.LogEvent(r.Context(), h.auditContext(r), event); err != nil {
		h.logger.Warn("failed to audit a group rule change", "error", err)
	}
}

// auditWidened records members added to a group that teams or scans use.
func (h *AssetGroupHandler) auditWidened(r *http.Request, id shared.ID, imp *asset.RuleImpact, how string, added int) {
	if h.auditService == nil || imp == nil || !imp.Widens {
		return
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetGroupRuleWidened, auditdom.ResourceTypeAssetGroup, id.String()).
		WithMessage("Assets were added to an asset group that teams or scans use").
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("how", how).WithMetadata("added", added).
		WithMetadata("teams", len(imp.Teams)).WithMetadata("scans", len(imp.Scans)).
		WithMetadata("privileged_team", imp.Privilege)
	if err := h.auditService.LogEvent(r.Context(), h.auditContext(r), event); err != nil {
		h.logger.Warn("failed to audit a group widening", "error", err)
	}
}

// PasteGroupAssetsRequest is a pasted list.
type PasteGroupAssetsRequest struct {
	// Text holds one name, IP address, CIDR range or http(s) URL per line.
	Text string `json:"text" validate:"required,max=2000000"`
	// CreateMissing creates the names that match no asset, through the scope
	// check: names outside the scope become candidates for review. Needs the
	// assets:write permission.
	CreateMissing bool `json:"create_missing"`
	// DryRun reports what the list matches without changing anything.
	DryRun bool `json:"dry_run"`
}

// PasteAssets handles POST /api/v1/asset-groups/{id}/assets/paste
// @Summary      Add a pasted list to a group
// @Description  Matches names, addresses, CIDR ranges and URLs (one per line, at most 10,000 lines) against the assets the caller can see and adds the matches to the group. Optionally creates the missing names through the scope check; names outside the organization's scope are held as candidates. Lines that are not a name, address, range or URL are reported as rejected.
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Asset Group ID"
// @Param        body  body      PasteGroupAssetsRequest  true  "List"
// @Success      200   {object}  asset.PasteResult
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/assets/paste [post]
func (h *AssetGroupHandler) PasteAssets(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}
	var req PasteGroupAssetsRequest
	if !decodeRuleBody(w, r, &req) {
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if req.CreateMissing && !req.DryRun && !middleware.HasPermission(r.Context(), string(permission.AssetsWrite)) {
		apierror.Forbidden("Creating assets needs the assets write permission").WriteJSON(w)
		return
	}
	res, err := h.service.PasteToGroup(r.Context(), middleware.MustGetTenantID(r.Context()), id, req.Text,
		asset.PasteOptions{DryRun: req.DryRun, CreateMissing: req.CreateMissing})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditWidened(r, id, res.Impact, "paste", res.Added)
	writeRuleJSON(w, http.StatusOK, res)
}

// AddMatchingRequest adds everything a filter matches.
type AddMatchingRequest struct {
	// Rule is a rule document (the same filter as the Assets list); every
	// asset it matches inside the caller's data scope becomes a member.
	Rule json.RawMessage `json:"rule" swaggertype:"object"`
}

// AddMatchingResponse says how many assets matched and joined.
type AddMatchingResponse struct {
	Matched int                 `json:"matched"`
	Added   int                 `json:"added"`
	Impact  *RuleImpactResponse `json:"impact,omitempty"`
}

// AddMatching handles POST /api/v1/asset-groups/{id}/assets/matching
// @Summary      Add all assets matching a filter to a group
// @Description  Adds every asset the filter matches inside the caller's data scope as a manual member, not only the page the caller sees (at most 50,000 members in a group).
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Asset Group ID"
// @Param        body  body      AddMatchingRequest  true  "Filter"
// @Success      200   {object}  AddMatchingResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/assets/matching [post]
func (h *AssetGroupHandler) AddMatching(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}
	var req AddMatchingRequest
	if !decodeRuleBody(w, r, &req) {
		return
	}
	added, matched, imp, err := h.service.AddMatchingToGroup(r.Context(), middleware.MustGetTenantID(r.Context()), id, req.Rule)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditWidened(r, id, imp, "matching", added)
	writeRuleJSON(w, http.StatusOK, AddMatchingResponse{Matched: matched, Added: added, Impact: imp})
}

// GroupHistoryEntry is one join or leave.
type GroupHistoryEntry struct {
	ID        string    `json:"id"`
	GroupID   string    `json:"group_id"`
	GroupName string    `json:"group_name,omitempty"`
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	Action    string    `json:"action" enums:"joined,left"`
	Source    string    `json:"source" enums:"rule,manual,paste"`
	Reason    string    `json:"reason" enums:"matches_rule,no_longer_matches,added_by_hand,added_by_paste,removed_by_hand"`
	CreatedAt time.Time `json:"created_at"`
}

func toGroupHistoryEntry(e *assetgroup.HistoryEntry) GroupHistoryEntry {
	return GroupHistoryEntry{ID: e.ID.String(), GroupID: e.GroupID.String(), GroupName: e.GroupName,
		AssetID: e.AssetID.String(), AssetName: e.AssetName, Action: e.Action, Source: e.Source,
		Reason: e.Reason, CreatedAt: e.CreatedAt}
}

func writeHistory(w http.ResponseWriter, res assetgroupPage) {
	data := make([]GroupHistoryEntry, len(res.Data))
	for i, e := range res.Data {
		data[i] = toGroupHistoryEntry(e)
	}
	writeRuleJSON(w, http.StatusOK, ListResponse[GroupHistoryEntry]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages})
}

// GetHistory handles GET /api/v1/asset-groups/{id}/history
// @Summary      Group membership history
// @Description  Who joined and left the group and why, newest first. A caller with a restricted data scope sees only the assets in their scope.
// @Tags         Asset Groups
// @Produce      json
// @Param        id        path      string  true   "Asset Group ID"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[GroupHistoryEntry]
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/history [get]
func (h *AssetGroupHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}
	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	res, err := h.service.ListGroupHistory(r.Context(), middleware.MustGetTenantID(r.Context()), id, paging.Page, paging.PerPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeHistory(w, res)
}

// GetAssetGroupHistory handles GET /api/v1/asset-groups/assets/{id}/history
// @Summary      Group history of an asset
// @Description  The asset groups an asset joined and left, and why, newest first.
// @Tags         Asset Groups
// @Produce      json
// @Param        id        path      string  true   "Asset ID"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[GroupHistoryEntry]
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/assets/{id}/history [get]
func (h *AssetGroupHandler) GetAssetGroupHistory(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	res, err := h.service.ListAssetGroupHistory(r.Context(), middleware.MustGetTenantID(r.Context()), id, paging.Page, paging.PerPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeHistory(w, res)
}
