package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

// WebPathEndpointResponse is an endpoint of a path tree level with the open
// findings at it. A finding linked to an endpoint (it names its method and
// endpoint) counts at that endpoint only; a finding with no link is mapped by
// its URL and counts at every method of the template.
type WebPathEndpointResponse struct {
	WebEndpointResponse
	FindingCount int    `json:"finding_count"`
	TopSeverity  string `json:"top_severity,omitempty"`
}

// WebPathsResponse is one level of an origin's path tree.
type WebPathsResponse struct {
	// Path is the node: "/" or a path template without a trailing slash.
	Path    string                   `json:"path"`
	Totals  webendpoint.PathTotals   `json:"totals"`
	Folders []webendpoint.PathFolder `json:"folders"`
	// FoldersTruncated: the level has more than 500 child nodes.
	FoldersTruncated bool                      `json:"folders_truncated"`
	Endpoints        []WebPathEndpointResponse `json:"endpoints"`
	EndpointTotal    int                       `json:"endpoint_total"`
	Page             int                       `json:"page"`
	PerPage          int                       `json:"per_page"`
	// NodeFindings: with findings=true, the open findings at the node's own
	// template, most severe first (at most 50; NodeFindingTotal counts all).
	NodeFindings     []webendpoint.NodeFinding `json:"node_findings,omitempty"`
	NodeFindingTotal int                       `json:"node_finding_total,omitempty"`
}

// webPathFindingsParam asks for the findings at the node's own template.
const webPathFindingsParam = "findings"

var webPathParams = map[string]bool{
	"path": true, "q": true, "hide_static": true, "hide_4xx": true, "with_findings": true, "include_gone": true,
	"scope": true, "method": true, "here": true, mcpParamPage: true, mcpParamPerPage: true, webPathFindingsParam: true,
}

// parseWebPathQuery reads the query strictly: an unknown or repeated
// parameter, a bad boolean or number is refused.
func parseWebPathQuery(r *http.Request) (webendpoint.PathQuery, bool) {
	vals := r.URL.Query()
	q := webendpoint.PathQuery{PerPage: 50}
	for k, v := range vals {
		if !webPathParams[k] || len(v) != 1 {
			return q, false
		}
	}
	flags := map[string]*bool{"hide_static": &q.HideStatic, "hide_4xx": &q.Hide4xx, "with_findings": &q.WithFindings,
		"include_gone": &q.IncludeGone, "here": &q.Here, webPathFindingsParam: &q.Findings}
	for k, dst := range flags {
		if s := vals.Get(k); s != "" {
			b, err := strconv.ParseBool(s)
			if err != nil {
				return q, false
			}
			*dst = b
		}
	}
	for k, dst := range map[string]*int{mcpParamPage: &q.Page, mcpParamPerPage: &q.PerPage} {
		if s := vals.Get(k); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				return q, false
			}
			*dst = n
		}
	}
	q.Path, q.Search, q.Scope = vals.Get("path"), vals.Get("q"), vals.Get("scope")
	if m := vals.Get("method"); m != "" {
		q.Methods = strings.Split(m, ",")
	}
	return q, true
}

// Paths handles GET /api/v1/assets/{id}/web-paths
// @Summary      One level of a web origin's path tree
// @Description  The origin's endpoints folded by path segment: the child nodes of `path` with the endpoints, the
// @Description  out-of-scope endpoints and the open findings under each, and one page of the endpoints under
// @Description  `path` (or only its own, with `here`). A finding linked to an endpoint counts at that endpoint;
// @Description  one with no link maps onto endpoints by path template, whatever the method. 404 for an asset of another tenant or outside the caller's data scope. Values are
// @Description  scan output: render as text.
// @Tags         Web Surface
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Origin asset ID"
// @Param        path  query  string  false  "Node: / or a path template without a trailing slash (default /)"
// @Param        q  query  string  false  "Keep endpoints whose path template contains this text"
// @Param        hide_static  query  boolean  false  "Hide style sheets, images, fonts, media and archives"
// @Param        hide_4xx  query  boolean  false  "Hide endpoints whose last answer was 400-499"
// @Param        with_findings  query  boolean  false  "Keep endpoints with open findings at their path"
// @Param        include_gone  query  boolean  false  "Also show endpoints not seen for 30 days"
// @Param        scope  query  string  false  "in or out (of scope)"  Enums(in, out)
// @Param        method  query  string  false  "Methods, comma list"
// @Param        here  query  boolean  false  "List only the endpoints of the node's own template"
// @Param        findings  query  boolean  false  "With here: also list the open findings at the node's own template"
// @Param        page  query  int  false  "Page (1-based)"
// @Param        per_page  query  int  false  "Endpoints per page, 0 to 100 (0: child nodes only; default 50)"
// @Success      200  {object}  WebPathsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/web-paths [get]
func (h *WebEndpointHandler) Paths(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return
	}
	assetID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Asset").WriteJSON(w)
		return
	}
	q, ok := parseWebPathQuery(r)
	if !ok {
		apierror.BadRequest("Invalid path tree query").WriteJSON(w)
		return
	}
	lvl, err := h.svc.Paths(r.Context(), tenantID, assetID, q)
	switch {
	case err == nil:
	case shared.IsNotFound(err):
		apierror.NotFound("Asset").WriteJSON(w)
		return
	case shared.IsValidation(err):
		apierror.BadRequest("Invalid path tree query").WriteJSON(w)
		return
	default:
		h.writeErr(w, err)
		return
	}
	resp := WebPathsResponse{Path: lvl.Path, Totals: lvl.Totals, Folders: lvl.Folders, FoldersTruncated: lvl.FoldersTruncated,
		Endpoints: make([]WebPathEndpointResponse, len(lvl.Endpoints)), EndpointTotal: lvl.EndpointTotal,
		Page: q.Page, PerPage: q.PerPage, NodeFindings: lvl.NodeFindings, NodeFindingTotal: lvl.NodeFindingTotal}
	if resp.Page < 1 {
		resp.Page = 1
	}
	if resp.Folders == nil {
		resp.Folders = []webendpoint.PathFolder{}
	}
	for i, e := range lvl.Endpoints {
		resp.Endpoints[i] = WebPathEndpointResponse{WebEndpointResponse: toWebEndpointResponse(e.Endpoint),
			FindingCount: e.Findings, TopSeverity: e.TopSeverity}
	}
	writeJSON(w, http.StatusOK, resp)
}
