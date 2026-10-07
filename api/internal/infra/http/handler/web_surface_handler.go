package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// The grouped web surface views (RFC-056): path patterns, origins with their
// coverage gap, the change feed and the sensitive-path catalog.

// WebPathPatternResponse is one path template across the caller's origins.
type WebPathPatternResponse struct {
	PathHash         string                    `json:"path_hash"`
	PathTemplate     string                    `json:"path_template"`
	Methods          []string                  `json:"methods"`
	EndpointCount    int64                     `json:"endpoint_count"`
	OriginCount      int64                     `json:"origin_count"`
	ReachableCount   int64                     `json:"reachable_count"`
	UnauthCount      int64                     `json:"unauth_count"`
	ExcludedUntested int64                     `json:"excluded_untested"`
	CatalogKey       string                    `json:"catalog_key,omitempty"`
	Catalog          *webendpoint.CatalogEntry `json:"catalog,omitempty"`
	FirstSeenAt      time.Time                 `json:"first_seen_at"`
	LastSeenAt       time.Time                 `json:"last_seen_at"`
}

// WebOriginResponse is one origin asset with its web surface counts and
// coverage gap.
type WebOriginResponse struct {
	OriginAssetID     string    `json:"origin_asset_id"`
	Origin            string    `json:"origin"`
	EndpointCount     int64     `json:"endpoint_count"`
	ActiveCount       int64     `json:"active_count"`
	ExcludedUntested  int64     `json:"excluded_untested"`
	ExcludedSensitive int64     `json:"excluded_sensitive"`
	UnauthSensitive   int64     `json:"unauth_sensitive"`
	NewLast7Days      int64     `json:"new_last_7_days"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

// WebEndpointEventResponse is one change of an endpoint.
type WebEndpointEventResponse struct {
	ID            string         `json:"id"`
	EndpointID    string         `json:"endpoint_id"`
	OriginAssetID string         `json:"origin_asset_id"`
	Origin        string         `json:"origin"`
	Method        string         `json:"method"`
	PathTemplate  string         `json:"path_template"`
	CatalogKey    string         `json:"catalog_key,omitempty"`
	Kind          string         `json:"kind" enums:"appeared,returned,gone,status_changed,auth_changed,param_added"`
	At            time.Time      `json:"at"`
	Detail        map[string]any `json:"detail"`
}

// WebPathCatalogResponse is the sensitive-path catalog.
type WebPathCatalogResponse struct {
	Version string                     `json:"version"`
	Entries []webendpoint.CatalogEntry `json:"entries"`
}

// ready answers 500 when the handler was built without its service.
func (h *WebEndpointHandler) ready(w http.ResponseWriter) bool {
	if h.svc == nil {
		apierror.InternalError(errors.New("web surface is not configured")).WriteJSON(w)
		return false
	}
	return true
}

func (h *WebEndpointHandler) groupRoute(name string) filterquery.Route {
	r := h.listRoute(name)
	r.Options.MaxPerPage = 100
	return r
}

// Patterns handles GET /api/v1/web-path-patterns
// @Summary      Web path patterns
// @Description  The endpoints the caller may see, grouped by path template across origins ("where does /actuator/env
// @Description  exist?"), most widespread first. Takes the web endpoint filters. Counted within the tenant and the
// @Description  caller's data scope only, never across tenants.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: web_endpoints GET /web-path-patterns
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
// @Success      200  {object}  ListResponse[WebPathPatternResponse]
// @Failure      400  {object}  apierror.Error
// @Router       /web-path-patterns [get]
func (h *WebEndpointHandler) Patterns(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	spec, ok := h.groupRoute("GET /web-path-patterns").ParseQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Patterns(r.Context(), webEndpointCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]WebPathPatternResponse, len(res.Data))
	for i, p := range res.Data {
		data[i] = WebPathPatternResponse{PathHash: p.PathHash, PathTemplate: p.PathTemplate, Methods: nonNilStrings(p.Methods),
			EndpointCount: p.EndpointCount, OriginCount: p.OriginCount, ReachableCount: p.ReachableCount, UnauthCount: p.UnauthCount,
			ExcludedUntested: p.ExcludedUntested, CatalogKey: p.CatalogKey, FirstSeenAt: p.FirstSeenAt, LastSeenAt: p.LastSeenAt}
		if p.CatalogKey != "" {
			data[i].Catalog = webendpoint.DefaultCatalog.ByKey(p.CatalogKey)
		}
	}
	writeJSON(w, http.StatusOK, ListResponse[WebPathPatternResponse]{Data: data, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages, Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages)})
}

// Origins handles GET /api/v1/web-origins
// @Summary      Web origins and their coverage gap
// @Description  The origin assets the caller may see that serve endpoints, with counts: endpoints, active, excluded and
// @Description  untested, the sensitive ones among those, and sensitive endpoints answering without authentication.
// @Description  An origin with excluded paths and no findings is not "safe": the excluded paths were never tested.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: web_endpoints GET /web-origins
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
// @Success      200  {object}  ListResponse[WebOriginResponse]
// @Failure      400  {object}  apierror.Error
// @Router       /web-origins [get]
func (h *WebEndpointHandler) Origins(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	spec, ok := h.groupRoute("GET /web-origins").ParseQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Origins(r.Context(), webEndpointCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]WebOriginResponse, len(res.Data))
	for i, o := range res.Data {
		data[i] = WebOriginResponse{OriginAssetID: o.OriginAssetID.String(), Origin: o.Origin, EndpointCount: o.EndpointCount,
			ActiveCount: o.ActiveCount, ExcludedUntested: o.ExcludedUntested, ExcludedSensitive: o.ExcludedSensitive,
			UnauthSensitive: o.UnauthSensitive, NewLast7Days: o.NewLast7Days, LastSeenAt: o.LastSeenAt}
	}
	writeJSON(w, http.StatusOK, ListResponse[WebOriginResponse]{Data: data, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages, Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages)})
}

// Events handles GET /api/v1/web-endpoint-events
// @Summary      Web surface change feed
// @Description  Endpoints that appeared, came back, went away, changed status or authentication, or gained a parameter,
// @Description  newest first, for the origins the caller may see. Kept 90 days.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: web_endpoint_events GET /web-endpoint-events
// @Param  kind  query  []string  false  "kind: any of (comma list)"  collectionFormat(csv)  Enums(appeared, returned, gone, status_changed, auth_changed, param_added)
// @Param  kind_not  query  []string  false  "kind: none of (comma list)"  collectionFormat(csv)  Enums(appeared, returned, gone, status_changed, auth_changed, param_added)
// @Param  origin_asset_id  query  []string  false  "origin asset id: any of (comma list)"  collectionFormat(csv)
// @Param  origin_asset_id_not  query  []string  false  "origin asset id: none of (comma list)"  collectionFormat(csv)
// @Param  endpoint_id  query  []string  false  "endpoint id: any of (comma list)"  collectionFormat(csv)
// @Param  at_gte  query  string  false  "at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  at_lte  query  string  false  "at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  at_gt  query  string  false  "at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  at_lt  query  string  false  "at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  sensitive  query  boolean  false  "sensitive equals"
// end filterspec-params
// @Success      200  {object}  ListResponse[WebEndpointEventResponse]
// @Failure      400  {object}  apierror.Error
// @Router       /web-endpoint-events [get]
func (h *WebEndpointHandler) Events(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	spec, ok := filterquery.Route{Name: "GET /web-endpoint-events", Registry: webendpoint.EventFields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}.ParseQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Events(r.Context(), webEndpointCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]WebEndpointEventResponse, len(res.Data))
	for i, e := range res.Data {
		data[i] = WebEndpointEventResponse{ID: e.ID.String(), EndpointID: e.EndpointID.String(), OriginAssetID: e.OriginAssetID.String(),
			Origin: e.Origin, Method: e.Method, PathTemplate: e.PathTemplate, CatalogKey: e.CatalogKey, Kind: e.Kind, At: e.At, Detail: e.Detail}
	}
	writeJSON(w, http.StatusOK, ListResponse[WebEndpointEventResponse]{Data: data, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages, Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages)})
}

// Catalog handles GET /api/v1/web-path-catalog
// @Summary      Sensitive-path catalog
// @Description  The platform-curated list of sensitive web paths endpoints are labelled with (admin consoles, debug and
// @Description  configuration endpoints, VCS and backup files). Platform data: the same for every tenant, never learned
// @Description  from tenant data.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  WebPathCatalogResponse
// @Router       /web-path-catalog [get]
func (h *WebEndpointHandler) Catalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, WebPathCatalogResponse{Version: webendpoint.DefaultCatalog.Version, Entries: webendpoint.DefaultCatalog.Entries})
}
