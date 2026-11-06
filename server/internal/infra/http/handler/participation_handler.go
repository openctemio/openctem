package handler

// Watchers of findings and remediation tasks (RFC-120). The routes gate the
// permission; the service checks that the caller can read the item and that a
// person added can too. Watcher names go only to callers who may read the
// member list and are not pentest clients.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/participation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	domain "github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ParticipationHandler serves watchers.
type ParticipationHandler struct {
	service *participation.Service
	logger  *logger.Logger
}

// NewParticipationHandler creates the handler.
func NewParticipationHandler(svc *participation.Service, log *logger.Logger) *ParticipationHandler {
	return &ParticipationHandler{service: svc, logger: log}
}

// WatcherResponse is one watcher.
type WatcherResponse struct {
	UserID    string  `json:"user_id"`
	Name      string  `json:"name"`
	AvatarURL string  `json:"avatar_url,omitempty"`
	Reason    string  `json:"reason"`
	AddedBy   *string `json:"added_by,omitempty"`
	// AddedByName is the name of who added this watcher; empty when they took
	// part themselves or the adder is no longer an active member.
	AddedByName string `json:"added_by_name,omitempty"`
	Since       string `json:"since"`
}

// ParticipantAssetOwnerResponse is the owner of the asset a finding is on (context only).
type ParticipantAssetOwnerResponse struct {
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Type      string `json:"type"`
}

// SubscriptionMeResponse is the caller's own subscription.
type SubscriptionMeResponse struct {
	// UserID is the caller (to find their own row in watchers).
	UserID string `json:"user_id,omitempty"`
	// State is subscribed, unsubscribed, or empty when the caller has no row.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ParticipantsResponse is the People section of an item.
type ParticipantsResponse struct {
	WatcherCount int                             `json:"watcher_count"`
	NamesVisible bool                            `json:"names_visible"`
	Watchers     []WatcherResponse               `json:"watchers"`
	AssetOwners  []ParticipantAssetOwnerResponse `json:"asset_owners"`
	Me           SubscriptionMeResponse          `json:"me"`
}

// SetSubscriptionRequest is the caller's own choice.
type SetSubscriptionRequest struct {
	State string `json:"state"`
}

// AddWatchersRequest names the people to add.
type AddWatchersRequest struct {
	UserIDs []string `json:"user_ids"`
}

func (h *ParticipationHandler) caller(r *http.Request) participation.Caller {
	uid, _ := shared.IDFromString(middleware.GetUserID(r.Context()))
	return participation.Caller{
		UserID:      uid,
		CanSeeNames: middleware.HasPermission(r.Context(), permission.MembersRead.String()),
	}
}

func (h *ParticipationHandler) auditContext(r *http.Request) audit.AuditContext {
	return audit.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
		SessionID:  middleware.GetSessionID(r.Context()),
	}
}

// item reads the tenant and the item id of the request.
func (h *ParticipationHandler) item(w http.ResponseWriter, r *http.Request, kind domain.ItemKind) (shared.ID, domain.Item, bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant").WriteJSON(w)
		return shared.ID{}, domain.Item{}, false
	}
	var raw string
	name := "finding"
	if kind == domain.ItemTask {
		raw, name = chi.URLParam(r, "task_id"), "remediation task"
	} else {
		raw = r.PathValue("id")
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		apierror.NotFound(name + " not found").WriteJSON(w)
		return shared.ID{}, domain.Item{}, false
	}
	return tid, domain.Item{Kind: kind, ID: id}, true
}

func (h *ParticipationHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("not found").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Access denied").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("participation", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

func toParticipantsResponse(p *participation.Participants) ParticipantsResponse {
	out := ParticipantsResponse{
		WatcherCount: p.WatcherCount, NamesVisible: p.NamesVisible,
		Watchers: []WatcherResponse{}, AssetOwners: []ParticipantAssetOwnerResponse{},
		Me: SubscriptionMeResponse{UserID: optIDString(p.Me.UserID), State: string(p.Me.State), Reason: string(p.Me.Reason)},
	}
	for _, w := range p.Watchers {
		out.Watchers = append(out.Watchers, WatcherResponse{UserID: w.UserID.String(), Name: w.Name, AvatarURL: w.AvatarURL,
			Reason: string(w.Reason), AddedBy: optIDStr(w.AddedBy), AddedByName: w.AddedByName, Since: w.Since})
	}
	for _, o := range p.AssetOwners {
		out.AssetOwners = append(out.AssetOwners, ParticipantAssetOwnerResponse{UserID: o.UserID.String(), Name: o.Name, AvatarURL: o.AvatarURL, Type: o.Type})
	}
	return out
}

func (h *ParticipationHandler) participants(w http.ResponseWriter, r *http.Request, kind domain.ItemKind) {
	tid, item, ok := h.item(w, r, kind)
	if !ok {
		return
	}
	p, err := h.service.Participants(r.Context(), tid, item, h.caller(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toParticipantsResponse(p))
}

func (h *ParticipationHandler) setSubscription(w http.ResponseWriter, r *http.Request, kind domain.ItemKind) {
	tid, item, ok := h.item(w, r, kind)
	if !ok {
		return
	}
	var req SetSubscriptionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	state, err := domain.ParseState(req.State)
	if err != nil {
		h.fail(w, err)
		return
	}
	if err := h.service.SetSelf(r.Context(), tid, item, h.caller(r), state); err != nil {
		h.fail(w, err)
		return
	}
	h.participants(w, r, kind)
}

func (h *ParticipationHandler) addWatchers(w http.ResponseWriter, r *http.Request, kind domain.ItemKind) {
	tid, item, ok := h.item(w, r, kind)
	if !ok {
		return
	}
	var req AddWatchersRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	ids := make([]shared.ID, 0, len(req.UserIDs))
	for _, s := range req.UserIDs {
		id, err := shared.IDFromString(s)
		if err != nil {
			// The same answer as a person who cannot be added.
			h.fail(w, domain.ErrCannotAdd)
			return
		}
		ids = append(ids, id)
	}
	if err := h.service.AddWatchers(r.Context(), tid, item, h.caller(r), ids, h.auditContext(r)); err != nil {
		h.fail(w, err)
		return
	}
	h.participants(w, r, kind)
}

func (h *ParticipationHandler) removeWatcher(w http.ResponseWriter, r *http.Request, kind domain.ItemKind, writePerm permission.Permission) {
	tid, item, ok := h.item(w, r, kind)
	if !ok {
		return
	}
	target, err := shared.IDFromString(chi.URLParam(r, "user_id"))
	if err != nil {
		apierror.NotFound("watcher not found").WriteJSON(w)
		return
	}
	mayOthers := middleware.HasPermission(r.Context(), writePerm.String())
	if err := h.service.RemoveWatcher(r.Context(), tid, item, h.caller(r), target, mayOthers, h.auditContext(r)); err != nil {
		h.fail(w, err)
		return
	}
	h.participants(w, r, kind)
}

// FindingParticipants handles GET /api/v1/findings/{id}/participants
// @Summary      Watchers of a finding
// @Description  The watchers the caller may see, the caller's own subscription and the owners of the finding's asset (context only). Names go only to callers with team:members:read who are not pentest clients; others get the count. Watchers who left or lost access are not listed.
// @Tags         Findings
// @Produce      json
// @Param        id  path  string  true  "Finding ID"
// @Success      200  {object}  ParticipantsResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/participants [get]
func (h *ParticipationHandler) FindingParticipants(w http.ResponseWriter, r *http.Request) {
	h.participants(w, r, domain.ItemFinding)
}

// FindingSetSubscription handles PUT /api/v1/findings/{id}/subscription
// @Summary      Watch or stop watching a finding
// @Description  The caller's own choice (the bell). Reading the finding is enough. An unsubscribe survives later participation.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id       path  string                  true  "Finding ID"
// @Param        request  body  SetSubscriptionRequest  true  "State"
// @Success      200  {object}  ParticipantsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/subscription [put]
func (h *ParticipationHandler) FindingSetSubscription(w http.ResponseWriter, r *http.Request) {
	h.setSubscription(w, r, domain.ItemFinding)
}

// FindingAddWatchers handles POST /api/v1/findings/{id}/watchers
// @Summary      Add watchers to a finding
// @Description  Adds up to 10 people, all or none. Each must be an active member who can read the finding, else 400 with one generic message. At most 50 watchers per finding. Audited.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id       path  string              true  "Finding ID"
// @Param        request  body  AddWatchersRequest  true  "People"
// @Success      200  {object}  ParticipantsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/watchers [post]
func (h *ParticipationHandler) FindingAddWatchers(w http.ResponseWriter, r *http.Request) {
	h.addWatchers(w, r, domain.ItemFinding)
}

// FindingRemoveWatcher handles DELETE /api/v1/findings/{id}/watchers/{user_id}
// @Summary      Remove a watcher from a finding
// @Description  A person removes themself with findings:read; removing someone else needs findings:assign (audited).
// @Tags         Findings
// @Produce      json
// @Param        id       path  string  true  "Finding ID"
// @Param        user_id  path  string  true  "User ID"
// @Success      200  {object}  ParticipantsResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/watchers/{user_id} [delete]
func (h *ParticipationHandler) FindingRemoveWatcher(w http.ResponseWriter, r *http.Request) {
	h.removeWatcher(w, r, domain.ItemFinding, permission.FindingsAssign)
}

// TaskParticipants handles GET /api/v1/remediation/tasks/{task_id}/participants
// @Summary      Watchers of a remediation task
// @Description  The watchers the caller may see and the caller's own subscription. Names go only to callers with team:members:read; others get the count.
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  ParticipantsResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/participants [get]
func (h *ParticipationHandler) TaskParticipants(w http.ResponseWriter, r *http.Request) {
	h.participants(w, r, domain.ItemTask)
}

// TaskSetSubscription handles PUT /api/v1/remediation/tasks/{task_id}/subscription
// @Summary      Watch or stop watching a remediation task
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                  true  "Task ID"
// @Param        request  body  SetSubscriptionRequest  true  "State"
// @Success      200  {object}  ParticipantsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/subscription [put]
func (h *ParticipationHandler) TaskSetSubscription(w http.ResponseWriter, r *http.Request) {
	h.setSubscription(w, r, domain.ItemTask)
}

// TaskAddWatchers handles POST /api/v1/remediation/tasks/{task_id}/watchers
// @Summary      Add watchers to a remediation task
// @Description  Adds up to 10 people, all or none. Each must be an active member who can read the task (one of its findings in their data scope). At most 50 watchers per task. Audited.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string              true  "Task ID"
// @Param        request  body  AddWatchersRequest  true  "People"
// @Success      200  {object}  ParticipantsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/watchers [post]
func (h *ParticipationHandler) TaskAddWatchers(w http.ResponseWriter, r *http.Request) {
	h.addWatchers(w, r, domain.ItemTask)
}

// TaskRemoveWatcher handles DELETE /api/v1/remediation/tasks/{task_id}/watchers/{user_id}
// @Summary      Remove a watcher from a remediation task
// @Description  A person removes themself with remediation:read; removing someone else needs remediation:write (audited).
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Param        user_id  path  string  true  "User ID"
// @Success      200  {object}  ParticipantsResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/watchers/{user_id} [delete]
func (h *ParticipationHandler) TaskRemoveWatcher(w http.ResponseWriter, r *http.Request) {
	h.removeWatcher(w, r, domain.ItemTask, permission.RemediationWrite)
}

// optIDString is the id as text, empty for the zero id.
func optIDString(id shared.ID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}
