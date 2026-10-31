package handler

// The Exposure Items view of the external attack surface
// (docs/architecture/exposure-taxonomy.md, "Exposure Items view"): the
// tenant's exposures with the asset each is on, its monitoring state and
// whether it is a primary asset, on the list query contract. Writes stay the
// typed exposure commands (/exposures/{id}/start-progress, /resolve,
// PATCH /severity, ...). Titles, summaries and asset names are scan output:
// clients render them as text.

import (
	"errors"
	"net/http"
	"time"

	exposuresvc "github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// ExposureItemResponse is one exposure of the view.
type ExposureItemResponse struct {
	ExposureResponse
	// AssetName and AssetType are empty for an exposure without an asset.
	AssetName string `json:"asset_name,omitempty"`
	AssetType string `json:"asset_type,omitempty"`
	// AssetMonitoringState is the derived monitoring state of the asset.
	AssetMonitoringState string `json:"asset_monitoring_state,omitempty"`
	// AssetPrimary: the asset is one of the organization's root domains.
	AssetPrimary bool `json:"asset_primary"`
}

// ExposureItemStatsResponse are the counts of one filtered set.
type ExposureItemStatsResponse struct {
	Total      int64            `json:"total"`
	BySeverity map[string]int64 `json:"by_severity"`
	ByCategory map[string]int64 `json:"by_category"`
	ByState    map[string]int64 `json:"by_state"`
}

// ExposureAssetGroupResponse is one asset of the filtered set with the
// counts of its exposures.
type ExposureAssetGroupResponse struct {
	AssetID              string           `json:"asset_id"`
	AssetName            string           `json:"asset_name"`
	AssetType            string           `json:"asset_type"`
	AssetMonitoringState string           `json:"asset_monitoring_state"`
	AssetPrimary         bool             `json:"asset_primary"`
	Total                int64            `json:"total"`
	BySeverity           map[string]int64 `json:"by_severity"`
	TopSeverity          string           `json:"top_severity,omitempty"`
	FirstSeenAt          time.Time        `json:"first_seen_at"`
	LastSeenAt           time.Time        `json:"last_seen_at"`
}

// SetItemsView wires the tenant's unclassified-scans mode, an input of the
// monitoring state (nil: unclassified assets count as not scanned, so they
// are never labeled monitored by mistake).
func (h *ExposureHandler) SetItemsView(policy AssetUnclassifiedPolicy) { h.unclassified = policy }

func (h *ExposureHandler) itemsScanned(r *http.Request, tenantID string) bool {
	return unclassifiedScannedBy(r, h.unclassified, tenantID)
}

func exposureItemsCaller(r *http.Request) exposuresvc.ItemsCaller {
	ctx := r.Context()
	return exposuresvc.ItemsCaller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.ReadsOnOwnScope(ctx),
	}
}

func (h *ExposureHandler) itemsRoute(name string) filterquery.Route {
	return filterquery.Route{Name: name, Registry: exposure.ItemFields,
		Options: filterspec.Options{Unknown: filterspec.UnknownStrict}, Logger: h.logger}
}

func (h *ExposureHandler) writeItemsErr(w http.ResponseWriter, err error) {
	if _, isFilter := filterspec.AsError(err); isFilter {
		filterquery.WriteError(w, err)
		return
	}
	if errors.Is(err, shared.ErrValidation) {
		apierror.BadRequest("Invalid request").WriteJSON(w)
		return
	}
	h.logger.Error("exposure items", "error", err)
	apierror.InternalError(err).WriteJSON(w)
}

// ListItems handles GET /api/v1/attack-surface/exposures
// @Summary      List exposure items
// @Description  The exposures the caller may see, with the asset each is on, its monitoring state and whether it is a
// @Description  primary asset. Filters follow the list query contract. Values are scan output: render as text.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: exposure_items GET /attack-surface/exposures
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  state  query  []string  false  "state: any of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  state_not  query  []string  false  "state: none of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  event_type  query  []string  false  "event type: any of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  event_type_not  query  []string  false  "event type: none of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  category  query  []string  false  "category: any of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  category_not  query  []string  false  "category: none of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)
// @Param  source_contains  query  string  false  "source contains"
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  asset_name  query  []string  false  "asset name: any of (comma list)"  collectionFormat(csv)
// @Param  asset_name_contains  query  string  false  "asset name contains"
// @Param  asset_name_not  query  []string  false  "asset name: none of (comma list)"  collectionFormat(csv)
// @Param  asset_type  query  []string  false  "asset type: any of (comma list)"  collectionFormat(csv)
// @Param  asset_type_not  query  []string  false  "asset type: none of (comma list)"  collectionFormat(csv)
// @Param  asset_monitoring_state  query  []string  false  "asset monitoring state: any of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  asset_monitoring_state_not  query  []string  false  "asset monitoring state: none of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  primary  query  boolean  false  "primary equals"
// @Param  severity_overridden  query  boolean  false  "severity overridden equals"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gte  query  string  false  "last seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lte  query  string  false  "last seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gt  query  string  false  "last seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lt  query  string  false  "last seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Success      200  {object}  ListResponse[ExposureItemResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/exposures [get]
func (h *ExposureHandler) ListItems(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.itemsRoute("GET /attack-surface/exposures").ParseQuery(w, r)
	if !ok {
		return
	}
	c := exposureItemsCaller(r)
	res, err := h.service.ListItems(r.Context(), c, spec, h.itemsScanned(r, c.TenantID))
	if err != nil {
		h.writeItemsErr(w, err)
		return
	}
	events := make([]*exposure.ExposureEvent, len(res.Data))
	for i, it := range res.Data {
		events[i] = it.Event
	}
	enrich := h.service.EnrichEvents(r.Context(), c.TenantID, events)
	data := make([]ExposureItemResponse, len(res.Data))
	ptrs := make([]*ExposureResponse, len(res.Data))
	for i, it := range res.Data {
		resp := toExposureResponse(it.Event)
		if enr, ok := enrich[it.Event.ID()]; ok {
			applyEnrichment(&resp, enr)
		}
		data[i] = ExposureItemResponse{ExposureResponse: resp, AssetName: it.AssetName, AssetType: it.AssetType,
			AssetMonitoringState: it.MonitoringState, AssetPrimary: it.Primary}
		ptrs[i] = &data[i].ExposureResponse
	}
	if err := h.attachPending(r, c.TenantID, ptrs, events); err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ListResponse[ExposureItemResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}

// ItemStats handles GET /api/v1/attack-surface/exposures/stats
// @Summary      Exposure item counts
// @Description  Counts by severity, display category and state for the same filters as the list.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: exposure_items GET /attack-surface/exposures/stats
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  state  query  []string  false  "state: any of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  state_not  query  []string  false  "state: none of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  event_type  query  []string  false  "event type: any of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  event_type_not  query  []string  false  "event type: none of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  category  query  []string  false  "category: any of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  category_not  query  []string  false  "category: none of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)
// @Param  source_contains  query  string  false  "source contains"
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  asset_name  query  []string  false  "asset name: any of (comma list)"  collectionFormat(csv)
// @Param  asset_name_contains  query  string  false  "asset name contains"
// @Param  asset_name_not  query  []string  false  "asset name: none of (comma list)"  collectionFormat(csv)
// @Param  asset_type  query  []string  false  "asset type: any of (comma list)"  collectionFormat(csv)
// @Param  asset_type_not  query  []string  false  "asset type: none of (comma list)"  collectionFormat(csv)
// @Param  asset_monitoring_state  query  []string  false  "asset monitoring state: any of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  asset_monitoring_state_not  query  []string  false  "asset monitoring state: none of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  primary  query  boolean  false  "primary equals"
// @Param  severity_overridden  query  boolean  false  "severity overridden equals"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gte  query  string  false  "last seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lte  query  string  false  "last seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gt  query  string  false  "last seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lt  query  string  false  "last seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Success      200  {object}  ExposureItemStatsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/exposures/stats [get]
func (h *ExposureHandler) ItemStats(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.itemsRoute("GET /attack-surface/exposures/stats").ParseQuery(w, r)
	if !ok {
		return
	}
	c := exposureItemsCaller(r)
	st, err := h.service.ItemStats(r.Context(), c, spec, h.itemsScanned(r, c.TenantID))
	if err != nil {
		h.writeItemsErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ExposureItemStatsResponse{Total: st.Total, BySeverity: st.BySeverity,
		ByCategory: st.ByCategory, ByState: st.ByState})
}

// ItemsByAsset handles GET /api/v1/attack-surface/exposures/assets
// @Summary      Exposure items grouped by asset
// @Description  The assets of the filtered set with the counts of their exposures, most severe first. Exposures
// @Description  without an asset are left out. Sort parameters are ignored.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// filterspec-params: exposure_items GET /attack-surface/exposures/assets
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info)
// @Param  state  query  []string  false  "state: any of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  state_not  query  []string  false  "state: none of (comma list)"  collectionFormat(csv)  Enums(active, in_progress, resolved, accepted, false_positive)
// @Param  event_type  query  []string  false  "event type: any of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  event_type_not  query  []string  false  "event type: none of (comma list)"  collectionFormat(csv)  Enums(port_open, port_closed, service_detected, service_changed, subdomain_discovered, subdomain_removed, certificate_expiring, certificate_expired, bucket_public, bucket_private, repo_public, repo_private, api_exposed, api_removed, credential_leaked, sensitive_data_exposed, misconfiguration, dns_change, ssl_issue, header_missing, identity_mfa_gap, identity_stale_principal, identity_overprivileged, dangling_cname, dangling_ns, email_security_weak, subdomain_takeover, lookalike_domain, web_interface_exposed, mcp_server_exposed, mail_server_blocklisted, custom)
// @Param  category  query  []string  false  "category: any of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  category_not  query  []string  false  "category: none of (comma list)"  collectionFormat(csv)  Enums(exposed_ports, web_interfaces, exposed_apis, ai_services, web_application, ssl_tls, certificates, hijackable_subdomains, email_security, cloud_storage, code_repositories, credentials_data, dns, lookalike_domains, identity, other)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)
// @Param  source_contains  query  string  false  "source contains"
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  asset_name  query  []string  false  "asset name: any of (comma list)"  collectionFormat(csv)
// @Param  asset_name_contains  query  string  false  "asset name contains"
// @Param  asset_name_not  query  []string  false  "asset name: none of (comma list)"  collectionFormat(csv)
// @Param  asset_type  query  []string  false  "asset type: any of (comma list)"  collectionFormat(csv)
// @Param  asset_type_not  query  []string  false  "asset type: none of (comma list)"  collectionFormat(csv)
// @Param  asset_monitoring_state  query  []string  false  "asset monitoring state: any of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  asset_monitoring_state_not  query  []string  false  "asset monitoring state: none of (comma list)"  collectionFormat(csv)  Enums(irrelevant, out_of_scope, inactive, pending_decision, unvalidated, not_monitored, monitored)
// @Param  primary  query  boolean  false  "primary equals"
// @Param  severity_overridden  query  boolean  false  "severity overridden equals"
// @Param  first_seen_gte  query  string  false  "first seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lte  query  string  false  "first seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_gt  query  string  false  "first seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_seen_lt  query  string  false  "first seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gte  query  string  false  "last seen at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lte  query  string  false  "last seen at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_gt  query  string  false  "last seen greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_lt  query  string  false  "last seen less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Success      200  {object}  ListResponse[ExposureAssetGroupResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /attack-surface/exposures/assets [get]
func (h *ExposureHandler) ItemsByAsset(w http.ResponseWriter, r *http.Request) {
	spec, ok := h.itemsRoute("GET /attack-surface/exposures/assets").ParseQuery(w, r)
	if !ok {
		return
	}
	c := exposureItemsCaller(r)
	res, err := h.service.ItemsByAsset(r.Context(), c, spec, h.itemsScanned(r, c.TenantID))
	if err != nil {
		h.writeItemsErr(w, err)
		return
	}
	data := make([]ExposureAssetGroupResponse, len(res.Data))
	for i, g := range res.Data {
		data[i] = ExposureAssetGroupResponse{AssetID: g.AssetID, AssetName: g.AssetName, AssetType: g.AssetType,
			AssetMonitoringState: g.MonitoringState, AssetPrimary: g.Primary, Total: g.Total, BySeverity: g.BySeverity,
			TopSeverity: g.TopSeverity, FirstSeenAt: g.FirstSeenAt, LastSeenAt: g.LastSeenAt}
	}
	writeJSON(w, http.StatusOK, ListResponse[ExposureAssetGroupResponse]{
		Data: data, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
		Links: NewPaginationLinks(r, res.Page, res.PerPage, res.TotalPages),
	})
}
