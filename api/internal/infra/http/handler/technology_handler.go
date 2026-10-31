package handler

import (
	"net/http"
	"time"

	technologyapp "github.com/openctemio/openctem/api/internal/app/technology"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/technology"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TechnologyHandler serves the Technologies view of the external attack
// surface: one row per technology and version across the assets the caller
// may see. Names, versions and vendors came from a scan: clients render
// them as text.
type TechnologyHandler struct {
	svc    *technologyapp.Service
	logger *logger.Logger
}

// NewTechnologyHandler creates the handler.
func NewTechnologyHandler(svc *technologyapp.Service, log *logger.Logger) *TechnologyHandler {
	return &TechnologyHandler{svc: svc, logger: log}
}

// TechnologyVersionResponse is one technology at one version.
type TechnologyVersionResponse struct {
	// Key is the normalised name, the value of the asset list's technology
	// filter; Name is the most common spelling.
	Key  string `json:"key"`
	Name string `json:"name"`
	// Version is "" when the tools could not tell it.
	Version      string   `json:"version"`
	VersionKnown bool     `json:"version_known"`
	Category     string   `json:"category"`
	Vendor       string   `json:"vendor,omitempty"`
	CPE          string   `json:"cpe,omitempty"`
	Sources      []string `json:"sources"`
	AssetCount   int64    `json:"asset_count"`
	// CVECount is how many CVEs of the corpus affect the matched software
	// version; TopCVE and TopCVSS the highest scored one.
	CVECount int64    `json:"cve_count"`
	TopCVE   string   `json:"top_cve,omitempty"`
	TopCVSS  *float64 `json:"top_cvss,omitempty"`
	// KEV: one of those CVEs is known exploited. ExploitAvailable: one has
	// a public exploit or is known exploited.
	KEV              bool      `json:"kev"`
	ExploitAvailable bool      `json:"exploit_available"`
	ActiveAlerts     int64     `json:"active_alerts"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
}

// TechnologyStatsResponse are the counts of one filtered set.
type TechnologyStatsResponse struct {
	Total          int64 `json:"total"`
	WithCVEs       int64 `json:"with_cves"`
	KEV            int64 `json:"kev"`
	UnknownVersion int64 `json:"unknown_version"`
	WithAlerts     int64 `json:"with_alerts"`
}

func toTechnologyVersionResponse(v *technology.Version) TechnologyVersionResponse {
	sources := v.Sources
	if sources == nil {
		sources = []string{}
	}
	return TechnologyVersionResponse{
		Key: v.Key, Name: v.Name, Version: v.Version, VersionKnown: v.Version != "", Category: v.Category,
		Vendor: v.Vendor, CPE: v.CPE, Sources: sources, AssetCount: v.AssetCount, CVECount: v.CVECount,
		TopCVE: v.TopCVE, TopCVSS: v.TopCVSS, KEV: v.KEV, ExploitAvailable: v.Exploit, ActiveAlerts: v.ActiveAlerts,
		FirstSeen: v.FirstSeen, LastSeen: v.LastSeen,
	}
}

func technologyCaller(r *http.Request) technologyapp.Caller {
	ctx := r.Context()
	return technologyapp.Caller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.ReadsOnOwnScope(ctx),
	}
}

func (h *TechnologyHandler) listRoute(name string) filterquery.Route {
	return filterquery.Route{Name: name, Registry: technology.Fields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}
}

func (h *TechnologyHandler) writeErr(w http.ResponseWriter, err error) {
	if _, isFilter := filterspec.AsError(err); isFilter {
		filterquery.WriteError(w, err)
		return
	}
	h.logger.Error("technologies", "error", err)
	apierror.InternalError(err).WriteJSON(w)
}

// List handles GET /api/v1/attack-surface/technologies
// @Summary      List technologies
// @Description  The technologies detected on the assets the caller may see, one row per technology and version, with
// @Description  the number of those assets and the CVE figures of the matched software version. Filters follow the
// @Description  list query contract and apply per asset. Values are scan output: render as text.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: technologies GET /attack-surface/technologies
// @Param  name  query  []string  false  "name: any of (comma list)"  collectionFormat(csv)
// @Param  name_contains  query  string  false  "name contains"
// @Param  name_not  query  []string  false  "name: none of (comma list)"  collectionFormat(csv)
// @Param  version  query  []string  false  "version: any of (comma list)"  collectionFormat(csv)
// @Param  version_contains  query  string  false  "version contains"
// @Param  version_not  query  []string  false  "version: none of (comma list)"  collectionFormat(csv)
// @Param  version_known  query  boolean  false  "version known equals"
// @Param  category  query  []string  false  "category: any of (comma list)"  collectionFormat(csv)  Enums(web_server, framework, language, js_library, cdn, hosting, waf, analytics, security_header, other)
// @Param  category_not  query  []string  false  "category: none of (comma list)"  collectionFormat(csv)  Enums(web_server, framework, language, js_library, cdn, hosting, waf, analytics, security_header, other)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)
// @Param  source_contains  query  string  false  "source contains"
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)
// @Param  vendor  query  []string  false  "vendor: any of (comma list)"  collectionFormat(csv)
// @Param  vendor_contains  query  string  false  "vendor contains"
// @Param  vendor_not  query  []string  false  "vendor: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  has_cves  query  boolean  false  "has cves equals"
// @Param  kev  query  boolean  false  "kev equals"
// @Param  last_seen_gte  query  string  false  "last seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lte  query  string  false  "last seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gt  query  string  false  "last seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lt  query  string  false  "last seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Success      200  {object}  ListResponse[TechnologyVersionResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/technologies [get]
func (h *TechnologyHandler) List(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /attack-surface/technologies").ParseQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.List(r.Context(), technologyCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	data := make([]TechnologyVersionResponse, len(res.Data))
	for i, v := range res.Data {
		data[i] = toTechnologyVersionResponse(v)
	}
	writeJSON(w, http.StatusOK, ListResponse[TechnologyVersionResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// Stats handles GET /api/v1/attack-surface/technologies/stats
// @Summary      Technology counts
// @Description  Counts of technology versions for the same filters as the list: all, with CVEs, with a known-exploited CVE, of
// @Description  unknown version and with open alerts.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: technologies GET /attack-surface/technologies/stats
// @Param  name  query  []string  false  "name: any of (comma list)"  collectionFormat(csv)
// @Param  name_contains  query  string  false  "name contains"
// @Param  name_not  query  []string  false  "name: none of (comma list)"  collectionFormat(csv)
// @Param  version  query  []string  false  "version: any of (comma list)"  collectionFormat(csv)
// @Param  version_contains  query  string  false  "version contains"
// @Param  version_not  query  []string  false  "version: none of (comma list)"  collectionFormat(csv)
// @Param  version_known  query  boolean  false  "version known equals"
// @Param  category  query  []string  false  "category: any of (comma list)"  collectionFormat(csv)  Enums(web_server, framework, language, js_library, cdn, hosting, waf, analytics, security_header, other)
// @Param  category_not  query  []string  false  "category: none of (comma list)"  collectionFormat(csv)  Enums(web_server, framework, language, js_library, cdn, hosting, waf, analytics, security_header, other)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)
// @Param  source_contains  query  string  false  "source contains"
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)
// @Param  vendor  query  []string  false  "vendor: any of (comma list)"  collectionFormat(csv)
// @Param  vendor_contains  query  string  false  "vendor contains"
// @Param  vendor_not  query  []string  false  "vendor: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  has_cves  query  boolean  false  "has cves equals"
// @Param  kev  query  boolean  false  "kev equals"
// @Param  last_seen_gte  query  string  false  "last seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lte  query  string  false  "last seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gt  query  string  false  "last seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lt  query  string  false  "last seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Success      200  {object}  TechnologyStatsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/technologies/stats [get]
func (h *TechnologyHandler) Stats(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.listRoute("GET /attack-surface/technologies/stats").ParseQuery(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Stats(r.Context(), technologyCaller(r), spec)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TechnologyStatsResponse(*st))
}
