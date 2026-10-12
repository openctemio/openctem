package handler

// Saved list views (UI style contract D15, docs/rfcs/RFC-048-list-query-contract.md §3.6).
// Tenant and owner come from the authenticated context, never from the body.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxSavedViewBody bounds a view request body (the filter is at most 32 KB).
const maxSavedViewBody = 48 << 10

// SavedViewHandler serves /api/v1/views.
type SavedViewHandler struct {
	service *savedviewapp.Service
	logger  *logger.Logger
}

// NewSavedViewHandler creates a SavedViewHandler.
func NewSavedViewHandler(svc *savedviewapp.Service, log *logger.Logger) *SavedViewHandler {
	return &SavedViewHandler{service: svc, logger: log}
}

// SavedViewResponse is one saved view.
type SavedViewResponse struct {
	ID          string          `json:"id"`
	Page        string          `json:"page"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Filter      json.RawMessage `json:"filter" swaggertype:"object"`
	GroupBy     string          `json:"group_by,omitempty"`
	Columns     []string        `json:"columns,omitempty"`
	Density     string          `json:"density,omitempty"`
	OwnerID     string          `json:"owner_id"`
	OwnerName   string          `json:"owner_name,omitempty"`
	GroupID     *string         `json:"group_id,omitempty"`
	GroupName   string          `json:"group_name,omitempty"`
	// IsOwner says whether the caller may edit or delete it (decision A1).
	IsOwner   bool      `json:"is_owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SavedViewRequest creates or updates a view. Send `filter` (a FilterDocument)
// or `query` (the page's flat GET params, e.g. "severity=critical&q=log4j").
type SavedViewRequest struct {
	// FromViewID duplicates a view the caller can see into a new personal
	// view (how a team member changes a shared view, decision A1); the
	// other fields are ignored then, except name.
	FromViewID  string          `json:"from_view_id,omitempty"`
	Page        string          `json:"page"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Filter      json.RawMessage `json:"filter,omitempty" swaggertype:"object"`
	Query       string          `json:"query,omitempty"`
	GroupID     *string         `json:"group_id,omitempty"`
	GroupBy     string          `json:"group_by,omitempty"`
	Columns     []string        `json:"columns,omitempty"`
	Density     string          `json:"density,omitempty"`
}

func savedViewCaller(r *http.Request) savedviewapp.Caller {
	ctx := r.Context()
	tid, _ := shared.IDFromString(middleware.GetTenantID(ctx))
	uid, _ := shared.IDFromString(middleware.GetUserID(ctx))
	return savedviewapp.Caller{
		TenantID: tid, UserID: uid,
		Has: func(p string) bool { return middleware.HasPermission(ctx, p) },
		Audit: auditapp.AuditContext{
			TenantID: middleware.GetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		},
	}
}

func toSavedViewResponse(v *savedview.View, caller shared.ID) SavedViewResponse {
	resp := SavedViewResponse{
		ID: v.ID.String(), Page: v.Page, Name: v.Name, Description: v.Description, Filter: v.Filter,
		GroupBy: v.GroupBy, Columns: v.Columns, Density: v.Density, OwnerID: v.OwnerID.String(), OwnerName: v.OwnerName,
		GroupName: v.GroupName, IsOwner: v.OwnerID == caller, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
	if v.GroupID != nil {
		g := v.GroupID.String()
		resp.GroupID = &g
	}
	return resp
}

func (h *SavedViewHandler) caller(w http.ResponseWriter, r *http.Request) (savedviewapp.Caller, bool) {
	c := savedViewCaller(r)
	if c.TenantID.IsZero() || c.UserID.IsZero() {
		// Views belong to a person; a user-less API key has none.
		apierror.Forbidden("Saved views need a signed-in user").WriteJSON(w)
		return c, false
	}
	return c, true
}

func (h *SavedViewHandler) writeErr(w http.ResponseWriter, err error) {
	if _, ok := filterspec.AsError(err); ok {
		filterquery.WriteError(w, err)
		return
	}
	switch {
	case errors.Is(err, savedview.ErrNotFound), errors.Is(err, savedview.ErrUnknownPage), errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Saved view").WriteJSON(w)
	case errors.Is(err, savedview.ErrNotOwner):
		apierror.Forbidden("Only the owner can change this view; duplicate it to make your own").WriteJSON(w)
	case errors.Is(err, savedview.ErrLimit):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, savedview.ErrInvalid):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("saved view", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

func (h *SavedViewHandler) decode(w http.ResponseWriter, r *http.Request) (savedviewapp.Input, bool) {
	req, ok := h.decodeRequest(w, r)
	if !ok {
		return savedviewapp.Input{}, false
	}
	return h.toInput(w, req)
}

func (h *SavedViewHandler) decodeRequest(w http.ResponseWriter, r *http.Request) (SavedViewRequest, bool) {
	var req SavedViewRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSavedViewBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return req, false
	}
	return req, true
}

func (h *SavedViewHandler) toInput(w http.ResponseWriter, req SavedViewRequest) (savedviewapp.Input, bool) {
	in := savedviewapp.Input{Page: req.Page, Name: req.Name, Description: req.Description, Filter: req.Filter,
		Query: req.Query, GroupBy: req.GroupBy, Columns: req.Columns, Density: req.Density}
	if string(req.Filter) == "null" {
		in.Filter = nil
	}
	if req.GroupID != nil && *req.GroupID != "" {
		id, err := shared.IDFromString(*req.GroupID)
		if err != nil {
			apierror.BadRequest("Invalid group_id").WriteJSON(w)
			return in, false
		}
		in.GroupID = &id
	}
	return in, true
}

func (h *SavedViewHandler) viewID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("Saved view").WriteJSON(w)
		return id, false
	}
	return id, true
}

func (h *SavedViewHandler) write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// List handles GET /api/v1/views
// @Summary      List saved views
// @Description  The caller's saved views of a page and the ones shared with their groups.
// @Tags         Saved views
// @Produce      json
// @Security     BearerAuth
// @Param        page  query  string  true  "Page"  Enums(findings)
// @Success      200  {object}  map[string]interface{}
// @Router       /views [get]
func (h *SavedViewHandler) List(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	page := r.URL.Query().Get("page")
	if page == "" {
		page = savedview.PageFindings
	}
	views, err := h.service.List(r.Context(), c, page)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]SavedViewResponse, 0, len(views))
	for _, v := range views {
		data = append(data, toSavedViewResponse(v, c.UserID))
	}
	h.write(w, http.StatusOK, map[string]any{"data": data})
}

// Get handles GET /api/v1/views/{id}
// @Summary      Get a saved view
// @Tags         Saved views
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "View ID"
// @Success      200  {object}  SavedViewResponse
// @Failure      404  {object}  map[string]interface{}
// @Router       /views/{id} [get]
func (h *SavedViewHandler) Get(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, ok := h.viewID(w, r)
	if !ok {
		return
	}
	v, err := h.service.Get(r.Context(), c, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, http.StatusOK, toSavedViewResponse(v, c.UserID))
}

// Create handles POST /api/v1/views
// @Summary      Save a view
// @Description  Saves a filter (a FilterDocument, or the page's flat query) and page state. Validated against
// @Description  the page's filter fields (400 INVALID_FILTER). group_id shares it with one of the caller's groups.
// @Description  from_view_id instead copies a view the caller can see into a new personal view (A1).
// @Tags         Saved views
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  SavedViewRequest  true  "View"
// @Success      201  {object}  SavedViewResponse
// @Failure      400  {object}  map[string]interface{}
// @Failure      409  {object}  map[string]interface{}  "Limit reached"
// @Router       /views [post]
func (h *SavedViewHandler) Create(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	req, ok := h.decodeRequest(w, r)
	if !ok {
		return
	}
	if req.FromViewID != "" {
		from, err := shared.IDFromString(req.FromViewID)
		if err != nil {
			apierror.NotFound("Saved view").WriteJSON(w)
			return
		}
		v, err := h.service.Duplicate(r.Context(), c, from, req.Name)
		if err != nil {
			h.writeErr(w, err)
			return
		}
		h.write(w, http.StatusCreated, toSavedViewResponse(v, c.UserID))
		return
	}
	in, ok := h.toInput(w, req)
	if !ok {
		return
	}
	v, err := h.service.Create(r.Context(), c, in)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, http.StatusCreated, toSavedViewResponse(v, c.UserID))
}

// Update handles PUT /api/v1/views/{id}
// @Summary      Update a saved view
// @Description  Only the owner may change a view (403 for a shared view of someone else; duplicate it instead).
// @Tags         Saved views
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path  string            true  "View ID"
// @Param        request  body  SavedViewRequest  true  "View"
// @Success      200  {object}  SavedViewResponse
// @Failure      403  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Router       /views/{id} [put]
func (h *SavedViewHandler) Update(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, ok := h.viewID(w, r)
	if !ok {
		return
	}
	in, ok := h.decode(w, r)
	if !ok {
		return
	}
	v, err := h.service.Update(r.Context(), c, id, in)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, http.StatusOK, toSavedViewResponse(v, c.UserID))
}

// Delete handles DELETE /api/v1/views/{id}
// @Summary      Delete a saved view
// @Tags         Saved views
// @Security     BearerAuth
// @Param        id  path  string  true  "View ID"
// @Success      204
// @Failure      403  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Router       /views/{id} [delete]
func (h *SavedViewHandler) Delete(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, ok := h.viewID(w, r)
	if !ok {
		return
	}
	if err := h.service.Delete(r.Context(), c, id); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
