package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	webendpointapp "github.com/openctemio/openctem/api/internal/app/webendpoint"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WebEndpointHandler serves the web surface sub-inventory (RFC-056):
// endpoints (method + path template) under their origin asset, and their
// parameter names. Every value it returns came from a scan: clients render
// it as text, never as a link that fetches.
type WebEndpointHandler struct {
	svc    *webendpointapp.Service
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewWebEndpointHandler creates the handler.
func NewWebEndpointHandler(svc *webendpointapp.Service, audit *auditapp.AuditService, log *logger.Logger) *WebEndpointHandler {
	return &WebEndpointHandler{svc: svc, audit: audit, logger: log}
}

// WebEndpointResponse is one endpoint.
type WebEndpointResponse struct {
	ID            string   `json:"id"`
	OriginAssetID string   `json:"origin_asset_id"`
	Origin        string   `json:"origin"`
	Method        string   `json:"method"`
	PathTemplate  string   `json:"path_template"`
	PathHash      string   `json:"path_hash"`
	Kind          string   `json:"kind"`
	Sources       []string `json:"sources"`
	ExamplePath   string   `json:"example_path,omitempty"`
	LastStatus    int      `json:"last_status,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	AuthState     string   `json:"auth_state"`
	Technologies  []string `json:"technologies"`
	Labels        []string `json:"labels"`
	State         string   `json:"state"`
	InScope       bool     `json:"in_scope"`
	CatalogKey    string   `json:"catalog_key,omitempty"`
	// Catalog describes the sensitive-path catalog entry (platform data).
	Catalog *webendpoint.CatalogEntry `json:"catalog,omitempty"`
	// ExclusionID names the path exclusion holding the endpoint
	// excluded-untested (in_scope false).
	ExclusionID   string     `json:"exclusion_id,omitempty"`
	ParamCount    int        `json:"param_count"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	LastChangedAt *time.Time `json:"last_changed_at,omitempty"`
	LastTool      string     `json:"last_tool,omitempty"`
}

// WebEndpointParamResponse is one parameter name of an endpoint (never a
// value).
type WebEndpointParamResponse struct {
	Location    string    `json:"location"`
	Name        string    `json:"name"`
	TypeHint    string    `json:"type_hint,omitempty"`
	Required    bool      `json:"required"`
	RiskHints   []string  `json:"risk_hints"`
	Sensitive   string    `json:"sensitive,omitempty"`
	Sources     []string  `json:"sources"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// WebEndpointStatsResponse are the counts of one filtered set.
type WebEndpointStatsResponse struct {
	Total            int64            `json:"total"`
	ByMethod         map[string]int64 `json:"by_method"`
	ByKind           map[string]int64 `json:"by_kind"`
	ByAuthState      map[string]int64 `json:"by_auth_state"`
	ByState          map[string]int64 `json:"by_state"`
	ExcludedUntested int64            `json:"excluded_untested"`
	// ExcludedSensitive: excluded-untested endpoints on the sensitive-path
	// catalog. UnauthSensitive: sensitive endpoints answering 2xx without
	// authentication.
	ExcludedSensitive int64 `json:"excluded_sensitive"`
	UnauthSensitive   int64 `json:"unauth_sensitive"`
}

// UpdateWebEndpointRequest changes an endpoint: state active or ignored,
// and labels (replaced whole).
type UpdateWebEndpointRequest struct {
	State  *string   `json:"state,omitempty" enums:"active,ignored"`
	Labels *[]string `json:"labels,omitempty"`
}

func toWebEndpointResponse(e *webendpoint.Endpoint) WebEndpointResponse {
	resp := WebEndpointResponse{
		ID: e.ID.String(), OriginAssetID: e.OriginAssetID.String(), Origin: e.Origin, Method: e.Method,
		PathTemplate: e.PathTemplate, PathHash: e.PathHash, Kind: e.Kind, Sources: nonNilStrings(e.Sources),
		ExamplePath: e.ExamplePath, LastStatus: e.LastStatus, ContentType: e.ContentType, AuthState: e.AuthState,
		Technologies: nonNilStrings(e.Technologies), Labels: nonNilStrings(e.Labels), State: string(e.State),
		InScope: e.InScope, CatalogKey: e.CatalogKey, ParamCount: e.ParamCount, FirstSeenAt: e.FirstSeenAt,
		LastSeenAt: e.LastSeenAt, LastChangedAt: e.LastChangedAt, LastTool: e.LastTool,
	}
	if e.CatalogKey != "" {
		resp.Catalog = webendpoint.DefaultCatalog.ByKey(e.CatalogKey)
	}
	if e.ExclusionID != nil {
		resp.ExclusionID = e.ExclusionID.String()
	}
	return resp
}

func webEndpointCaller(r *http.Request) webendpointapp.Caller {
	ctx := r.Context()
	return webendpointapp.Caller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.IsAPIKeyAuthenticated(ctx),
	}
}

func (h *WebEndpointHandler) listRoute(name string) filterquery.Route {
	return filterquery.Route{Name: name, Registry: webendpoint.Fields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}
}

func (h *WebEndpointHandler) writeErr(w http.ResponseWriter, err error) {
	if _, isFilter := filterspec.AsError(err); isFilter {
		filterquery.WriteError(w, err)
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Web endpoint").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("web endpoints", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

func (h *WebEndpointHandler) writeList(w http.ResponseWriter, r *http.Request, spec *filterspec.Spec) {
	res, err := h.svc.List(r.Context(), webEndpointCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]WebEndpointResponse, len(res.Data))
	for i, e := range res.Data {
		data[i] = toWebEndpointResponse(e)
	}
	writeJSON(w, http.StatusOK, ListResponse[WebEndpointResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// List handles GET /api/v1/web-endpoints
// @Summary      List web endpoints
// @Description  The endpoints (method + path template) web origins serve, across the tenant's origin assets the
// @Description  caller may see. Filters follow the list query contract (RFC-048). Values are scan output: render as text.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: web_endpoints GET /web-endpoints
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  origin_asset_id  query  []string  false  "origin asset id: any of (comma list)"  collectionFormat(csv)
// @Param  origin_asset_id_not  query  []string  false  "origin asset id: none of (comma list)"  collectionFormat(csv)
// @Param  method  query  []string  false  "method: any of (comma list)"  collectionFormat(csv)  Enums(GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY)
// @Param  method_not  query  []string  false  "method: none of (comma list)"  collectionFormat(csv)  Enums(GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY)
// @Param  kind  query  []string  false  "kind: any of (comma list)"  collectionFormat(csv)  Enums(page, api, script, form, graphql, websocket, other)
// @Param  kind_not  query  []string  false  "kind: none of (comma list)"  collectionFormat(csv)  Enums(page, api, script, form, graphql, websocket, other)
// @Param  auth_state  query  []string  false  "auth state: any of (comma list)"  collectionFormat(csv)  Enums(none, required, redirect_login, unknown)
// @Param  auth_state_not  query  []string  false  "auth state: none of (comma list)"  collectionFormat(csv)  Enums(none, required, redirect_login, unknown)
// @Param  state  query  []string  false  "state: any of (comma list)"  collectionFormat(csv)  Enums(active, gone, ignored)
// @Param  state_not  query  []string  false  "state: none of (comma list)"  collectionFormat(csv)  Enums(active, gone, ignored)
// @Param  in_scope  query  boolean  false  "in scope equals"
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)  Enums(crawl, js, sitemap, robots, spec, har, archive, dast, probe)
// @Param  label  query  []string  false  "label: any of (comma list)"  collectionFormat(csv)
// @Param  catalog_key  query  []string  false  "catalog key: any of (comma list)"  collectionFormat(csv)
// @Param  catalog_key_not  query  []string  false  "catalog key: none of (comma list)"  collectionFormat(csv)
// @Param  sensitive  query  boolean  false  "sensitive equals"
// @Param  path_hash  query  []string  false  "path hash: any of (comma list)"  collectionFormat(csv)
// @Param  path_template  query  string  false  "path template contains"
// @Param  path_template_contains  query  string  false  "path template contains"
// @Param  last_status  query  []integer  false  "last status: any of (comma list)"  collectionFormat(csv)
// @Param  last_status_gte  query  integer  false  "last status at least"
// @Param  last_status_lte  query  integer  false  "last status at most"
// @Param  param_count_gte  query  integer  false  "param count at least"
// @Param  param_count_lte  query  integer  false  "param count at most"
// @Param  first_seen_at_gte  query  string  false  "first seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_lte  query  string  false  "first seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_gt  query  string  false  "first seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_lt  query  string  false  "first seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gte  query  string  false  "last seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lte  query  string  false  "last seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gt  query  string  false  "last seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lt  query  string  false  "last seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_gte  query  string  false  "last changed at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_lte  query  string  false  "last changed at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_gt  query  string  false  "last changed at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_lt  query  string  false  "last changed at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// end filterspec-params
// @Success      200  {object}  ListResponse[WebEndpointResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /web-endpoints [get]
func (h *WebEndpointHandler) List(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /web-endpoints").ParseQuery(w, r)
	if !ok {
		return
	}
	h.writeList(w, r, spec)
}

// ListByAsset handles GET /api/v1/assets/{id}/web-endpoints
// @Summary      List the web endpoints of one origin asset
// @Description  The endpoints of one origin (http_service) asset. 404 for an asset the caller may not see.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Origin asset ID"
// @Param        page  query  int  false  "Page"
// @Param        per_page  query  int  false  "Page size (max 100)"
// @Param        sort  query  string  false  "Sort keys, e.g. -last_seen_at"
// @Param        q  query  string  false  "Search the path template"
// @Success      200  {object}  ListResponse[WebEndpointResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/web-endpoints [get]
func (h *WebEndpointHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	assetID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Asset").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	q.Del("origin_asset_id")
	spec, ok := h.listRoute("GET /assets/{id}/web-endpoints").ParseValues(w, r, q)
	if !ok {
		return
	}
	leaf := &filterspec.Node{Leaf: &filterspec.Leaf{Field: "origin_asset_id", Op: filterspec.OpIn, Values: []any{assetID.String()}}}
	if spec.Root == nil {
		spec.Root = leaf
	} else {
		spec.Root = &filterspec.Node{All: []*filterspec.Node{spec.Root, leaf}}
	}
	h.writeList(w, r, spec)
}

// Stats handles GET /api/v1/web-endpoints/stats
// @Summary      Web endpoint counts
// @Description  Counts by method, kind, auth state and state, and the endpoints under a scope exclusion (recorded,
// @Description  never tested), for the same filters as the list.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: web_endpoints GET /web-endpoints/stats
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  origin_asset_id  query  []string  false  "origin asset id: any of (comma list)"  collectionFormat(csv)
// @Param  origin_asset_id_not  query  []string  false  "origin asset id: none of (comma list)"  collectionFormat(csv)
// @Param  method  query  []string  false  "method: any of (comma list)"  collectionFormat(csv)  Enums(GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY)
// @Param  method_not  query  []string  false  "method: none of (comma list)"  collectionFormat(csv)  Enums(GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY)
// @Param  kind  query  []string  false  "kind: any of (comma list)"  collectionFormat(csv)  Enums(page, api, script, form, graphql, websocket, other)
// @Param  kind_not  query  []string  false  "kind: none of (comma list)"  collectionFormat(csv)  Enums(page, api, script, form, graphql, websocket, other)
// @Param  auth_state  query  []string  false  "auth state: any of (comma list)"  collectionFormat(csv)  Enums(none, required, redirect_login, unknown)
// @Param  auth_state_not  query  []string  false  "auth state: none of (comma list)"  collectionFormat(csv)  Enums(none, required, redirect_login, unknown)
// @Param  state  query  []string  false  "state: any of (comma list)"  collectionFormat(csv)  Enums(active, gone, ignored)
// @Param  state_not  query  []string  false  "state: none of (comma list)"  collectionFormat(csv)  Enums(active, gone, ignored)
// @Param  in_scope  query  boolean  false  "in scope equals"
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)  Enums(crawl, js, sitemap, robots, spec, har, archive, dast, probe)
// @Param  label  query  []string  false  "label: any of (comma list)"  collectionFormat(csv)
// @Param  catalog_key  query  []string  false  "catalog key: any of (comma list)"  collectionFormat(csv)
// @Param  catalog_key_not  query  []string  false  "catalog key: none of (comma list)"  collectionFormat(csv)
// @Param  sensitive  query  boolean  false  "sensitive equals"
// @Param  path_hash  query  []string  false  "path hash: any of (comma list)"  collectionFormat(csv)
// @Param  path_template  query  string  false  "path template contains"
// @Param  path_template_contains  query  string  false  "path template contains"
// @Param  last_status  query  []integer  false  "last status: any of (comma list)"  collectionFormat(csv)
// @Param  last_status_gte  query  integer  false  "last status at least"
// @Param  last_status_lte  query  integer  false  "last status at most"
// @Param  param_count_gte  query  integer  false  "param count at least"
// @Param  param_count_lte  query  integer  false  "param count at most"
// @Param  first_seen_at_gte  query  string  false  "first seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_lte  query  string  false  "first seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_gt  query  string  false  "first seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_seen_at_lt  query  string  false  "first seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gte  query  string  false  "last seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lte  query  string  false  "last seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gt  query  string  false  "last seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lt  query  string  false  "last seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_gte  query  string  false  "last changed at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_lte  query  string  false  "last changed at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_gt  query  string  false  "last changed at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_changed_at_lt  query  string  false  "last changed at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// end filterspec-params
// @Success      200  {object}  WebEndpointStatsResponse
// @Failure      400  {object}  apierror.Error
// @Router       /web-endpoints/stats [get]
func (h *WebEndpointHandler) Stats(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /web-endpoints/stats").ParseQuery(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Stats(r.Context(), webEndpointCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, WebEndpointStatsResponse(*st))
}

func (h *WebEndpointHandler) ids(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Web endpoint").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, id, true
}

// Get handles GET /api/v1/web-endpoints/{id}
// @Summary      Get a web endpoint
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Web endpoint ID"
// @Success      200  {object}  WebEndpointResponse
// @Failure      404  {object}  apierror.Error
// @Router       /web-endpoints/{id} [get]
func (h *WebEndpointHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	e, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toWebEndpointResponse(e))
}

// Parameters handles GET /api/v1/web-endpoints/{id}/parameters
// @Summary      List the parameters of a web endpoint
// @Description  Parameter names and locations with name-derived risk hints. Values are never stored.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Web endpoint ID"
// @Success      200  {object}  object{data=[]WebEndpointParamResponse}
// @Failure      404  {object}  apierror.Error
// @Router       /web-endpoints/{id}/parameters [get]
func (h *WebEndpointHandler) Parameters(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	params, err := h.svc.Params(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]WebEndpointParamResponse, len(params))
	for i, p := range params {
		data[i] = WebEndpointParamResponse{Location: p.Location, Name: p.Name, TypeHint: p.TypeHint, Required: p.Required,
			RiskHints: nonNilStrings(p.RiskHints), Sensitive: p.Sensitive, Sources: nonNilStrings(p.Sources),
			FirstSeenAt: p.FirstSeenAt, LastSeenAt: p.LastSeenAt}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// Update handles PATCH /api/v1/web-endpoints/{id}
// @Summary      Update a web endpoint
// @Description  Set the state (active or ignored) and the labels. Audit-logged.
// @Tags         Web Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Web endpoint ID"
// @Param        body  body  UpdateWebEndpointRequest  true  "Changes"
// @Success      200  {object}  WebEndpointResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /web-endpoints/{id} [patch]
func (h *WebEndpointHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req UpdateWebEndpointRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	e, err := h.svc.Update(r.Context(), tenantID, id, webendpointapp.UpdateInput{State: req.State, Labels: req.Labels})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	if h.audit != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionAssetUpdated, auditdom.ResourceTypeAsset, e.OriginAssetID.String()).
			WithResourceName(e.Origin).
			WithMessage("Web endpoint updated").
			WithMetadata("web_endpoint_id", e.ID.String()).
			WithMetadata("method", e.Method).
			WithMetadata("path_template", e.PathTemplate).
			WithMetadata("state", string(e.State)).
			WithMetadata("labels", nonNilStrings(e.Labels)).
			WithSeverity(auditdom.SeverityLow)
		_ = h.audit.LogEvent(r.Context(), auditapp.AuditContext{
			TenantID: tenantID.String(), ActorID: middleware.GetUserID(r.Context()), ActorEmail: auditActorEmail(r.Context()),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		}, event)
	}
	writeJSON(w, http.StatusOK, toWebEndpointResponse(e))
}
