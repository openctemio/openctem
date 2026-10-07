package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/finding"
	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ValidationRunner dispatches a CTEM Stage-4 validation job for a finding and
// returns the command ID it was queued under. Implemented by
// *validation.RunService.
type ValidationRunner interface {
	ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error)
}

// FindingActionsHandler handles closed-loop finding lifecycle operations.
type FindingActionsHandler struct {
	service          *finding.FindingActionsService
	validationRunner ValidationRunner
	savedViews       *savedviewapp.Service
	logger           *logger.Logger
}

// NewFindingActionsHandler creates a new FindingActionsHandler.
func NewFindingActionsHandler(svc *finding.FindingActionsService, log *logger.Logger) *FindingActionsHandler {
	return &FindingActionsHandler{service: svc, logger: log}
}

// SetValidationRunner wires the validation-run service. When unset, the
// validate endpoint responds 503 (feature not configured).
func (h *FindingActionsHandler) SetValidationRunner(r ValidationRunner) {
	h.validationRunner = r
}

// SetSavedViews wires saved views, for ?view=<id> on the grouped view.
func (h *FindingActionsHandler) SetSavedViews(svc *savedviewapp.Service) {
	h.savedViews = svc
}

// --- Group View ---

// findingGroupByDimensions are exactly the dimensions the repository implements
// (FindingRepository.ListFindingGroups). The list had drifted: it rejected
// owner_id, component_id and finding_type, which the UI offers, with 400 and
// let status and type through to a 500.
var findingGroupByDimensions = map[string]bool{
	"cve_id": true, "rule_id": true, "asset_id": true, "owner_id": true, "component_id": true,
	"severity": true, "source": true, "finding_type": true, "family": true,
}

// findingGroupsRoute is GET /findings/groups on the list query contract:
// the same filter params (and old aliases) as GET /findings, plus group_by.
func (h *FindingActionsHandler) findingGroupsRoute() filterquery.Route {
	return filterquery.Route{
		Name:         "GET /findings/groups",
		Registry:     vulnerability.FindingFields,
		Options:      filterspec.Options{Unknown: filterspec.UnknownWarn, Extra: []string{"group_by"}},
		DeprecatedAt: findingsListDeprecatedAt,
		SunsetAt:     findingsListSunsetAt,
		Logger:       h.logger,
	}
}

// ListFindingGroups handles GET /api/v1/findings/groups
// @Summary      Group findings
// @Description  Findings grouped by one dimension, with per-group counts. Takes every filter param of GET /findings
// @Description  (RFC-048), so a grouped view counts exactly the rows the list shows.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        group_by  query  string  false  "cve_id (default), rule_id, asset_id, owner_id, component_id, severity, source, finding_type, family"
// filterspec-params: findings GET /findings/groups
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  branch_id  query  []string  false  "branch id: any of (comma list)"  collectionFormat(csv)
// @Param  open_on_branch_id  query  []string  false  "open on branch id: any of (comma list)"  collectionFormat(csv)
// @Param  fixed_on_branch_id  query  []string  false  "fixed on branch id: any of (comma list)"  collectionFormat(csv)
// @Param  branch_only  query  boolean  false  "branch only equals"
// @Param  component_id  query  []string  false  "component id: any of (comma list)"  collectionFormat(csv)
// @Param  component_id_not  query  []string  false  "component id: none of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id  query  []string  false  "vulnerability id: any of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id_not  query  []string  false  "vulnerability id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
// @Param  state  query  string  false  "state equals"  Enums(open, fixed, dispositioned, all)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  sla_status  query  []string  false  "sla status: any of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  sla_status_not  query  []string  false  "sla status: none of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  priority_class  query  []string  false  "priority class: any of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  priority_class_not  query  []string  false  "priority class: none of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  cve_id  query  []string  false  "cve id: any of (comma list)"  collectionFormat(csv)
// @Param  cve_id_not  query  []string  false  "cve id: none of (comma list)"  collectionFormat(csv)
// @Param  family  query  []string  false  "family: any of (comma list)"  collectionFormat(csv)
// @Param  family_not  query  []string  false  "family: none of (comma list)"  collectionFormat(csv)
// @Param  finding_type  query  []string  false  "finding type: any of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3)
// @Param  finding_type_not  query  []string  false  "finding type: none of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3)
// @Param  is_in_kev  query  boolean  false  "is in kev equals"
// @Param  is_reachable  query  boolean  false  "is reachable equals"
// @Param  epss_score_gte  query  number  false  "epss score at least"
// @Param  epss_score_lte  query  number  false  "epss score at most"
// @Param  epss_score_gt  query  number  false  "epss score greater than"
// @Param  epss_score_lt  query  number  false  "epss score less than"
// @Param  tool_name  query  []string  false  "tool name: any of (comma list)"  collectionFormat(csv)
// @Param  tool_name_not  query  []string  false  "tool name: none of (comma list)"  collectionFormat(csv)
// @Param  rule_id  query  []string  false  "rule id: any of (comma list)"  collectionFormat(csv)
// @Param  rule_id_not  query  []string  false  "rule id: none of (comma list)"  collectionFormat(csv)
// @Param  scan_id  query  []string  false  "scan id: any of (comma list)"  collectionFormat(csv)
// @Param  scan_id_not  query  []string  false  "scan id: none of (comma list)"  collectionFormat(csv)
// @Param  file_path  query  string  false  "file path contains"
// @Param  file_path_contains  query  string  false  "file path contains"
// @Param  asset_tag  query  []string  false  "asset tag: any of (comma list)"  collectionFormat(csv)
// @Param  asset_tag_not  query  []string  false  "asset tag: none of (comma list)"  collectionFormat(csv)
// @Param  related_to  query  string  false  "related to equals"  Enums(me)
// @Param  cvss_score_gte  query  number  false  "cvss score at least"
// @Param  cvss_score_lte  query  number  false  "cvss score at most"
// @Param  cvss_score_gt  query  number  false  "cvss score greater than"
// @Param  cvss_score_lt  query  number  false  "cvss score less than"
// @Param  first_detected_at_gte  query  string  false  "first detected at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_lte  query  string  false  "first detected at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_gt  query  string  false  "first detected at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_lt  query  string  false  "first detected at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gte  query  string  false  "last seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lte  query  string  false  "last seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gt  query  string  false  "last seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lt  query  string  false  "last seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_gte  query  string  false  "resolved at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_lte  query  string  false  "resolved at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_gt  query  string  false  "resolved at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_lt  query  string  false  "resolved at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  network_port  query  []integer  false  "network port: any of (comma list)"  collectionFormat(csv)
// @Param  network_port_not  query  []integer  false  "network port: none of (comma list)"  collectionFormat(csv)
// @Param  network_port_gte  query  integer  false  "network port at least"
// @Param  network_port_lte  query  integer  false  "network port at most"
// @Param  network_transport  query  []string  false  "network transport: any of (comma list)"  collectionFormat(csv)  Enums(tcp, udp, sctp)
// @Param  network_transport_not  query  []string  false  "network transport: none of (comma list)"  collectionFormat(csv)  Enums(tcp, udp, sctp)
// @Param  network_service  query  []string  false  "network service: any of (comma list)"  collectionFormat(csv)
// @Param  network_service_not  query  []string  false  "network service: none of (comma list)"  collectionFormat(csv)
// @Param  assigned_to  query  []string  false  "assigned to: any of (comma list)"  collectionFormat(csv)
// @Param  assigned_to_null  query  boolean  false  "assigned to is unset (true) or set (false)"
// @Param  assigned_to_not  query  []string  false  "assigned to: none of (comma list)"  collectionFormat(csv)
// @Param  asset_criticality  query  []string  false  "asset criticality: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  asset_criticality_not  query  []string  false  "asset criticality: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  asset_owner_id  query  []string  false  "asset owner id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_owner_id_null  query  boolean  false  "asset owner id is unset (true) or set (false)"
// @Param  exploit_available  query  boolean  false  "exploit available equals"
// @Param  created_at_gte  query  string  false  "created at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_lte  query  string  false  "created at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_gt  query  string  false  "created at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_lt  query  string  false  "created at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_gte  query  string  false  "updated at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_lte  query  string  false  "updated at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_gt  query  string  false  "updated at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_lt  query  string  false  "updated at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// end filterspec-params
// @Param        view   query  string  false  "Saved view ID: its filter, with the other params overriding it field by field"
// @Param        q         query  string  false  "Free text"
// @Param        sort      query  string  false  "Ignored by groups (accepted for URL parity with the list)"
// @Param        page      query  int     false  "Page number"  default(1)
// @Param        per_page  query  int     false  "Groups per page"  default(50)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Response
// @Router       /findings/groups [get]
func (h *FindingActionsHandler) ListFindingGroups(w http.ResponseWriter, r *http.Request) {
	groupBy := r.URL.Query().Get("group_by")
	if groupBy == "" {
		groupBy = "cve_id"
	} else if !findingGroupByDimensions[groupBy] {
		apierror.BadRequest("Invalid group_by value").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	if !rewriteBranchStatus(w, q) {
		return
	}
	spec, ok := h.findingGroupsRoute().ParseValues(w, r, q)
	if !ok {
		return
	}
	if spec, ok = applySavedView(h.savedViews, savedview.PageFindings, w, r, spec); !ok {
		return
	}
	perPage := spec.PerPage
	if perPage == 0 {
		perPage = 50
	}

	result, err := h.service.ListFindingGroupsBySpec(r.Context(), filterCaller(r), groupBy, spec, pagination.New(spec.Page, perPage))
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data": result.Data,
		"pagination": map[string]any{
			"total":    result.Total,
			"page":     result.Page,
			"per_page": result.PerPage,
		},
	})
}

// --- Related CVEs ---

// GetRelatedCVEs handles GET /api/v1/findings/related-cves/{cveId}
// @Summary      Related CVEs
// @Description  CVEs sharing a component with the given CVE, among the open findings the filter selects
// @Description  (the params of GET /findings, RFC-048). The source CVE's components come only from findings
// @Description  the caller may see.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        cveId  path  string  true  "CVE id"
// filterspec-params: findings GET /findings/related-cves/{cveId}
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  asset_id  query  []string  false  "asset id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_id_not  query  []string  false  "asset id: none of (comma list)"  collectionFormat(csv)
// @Param  branch_id  query  []string  false  "branch id: any of (comma list)"  collectionFormat(csv)
// @Param  open_on_branch_id  query  []string  false  "open on branch id: any of (comma list)"  collectionFormat(csv)
// @Param  fixed_on_branch_id  query  []string  false  "fixed on branch id: any of (comma list)"  collectionFormat(csv)
// @Param  branch_only  query  boolean  false  "branch only equals"
// @Param  component_id  query  []string  false  "component id: any of (comma list)"  collectionFormat(csv)
// @Param  component_id_not  query  []string  false  "component id: none of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id  query  []string  false  "vulnerability id: any of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id_not  query  []string  false  "vulnerability id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
// @Param  state  query  string  false  "state equals"  Enums(open, fixed, dispositioned, all)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  sla_status  query  []string  false  "sla status: any of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  sla_status_not  query  []string  false  "sla status: none of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  priority_class  query  []string  false  "priority class: any of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  priority_class_not  query  []string  false  "priority class: none of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  cve_id  query  []string  false  "cve id: any of (comma list)"  collectionFormat(csv)
// @Param  cve_id_not  query  []string  false  "cve id: none of (comma list)"  collectionFormat(csv)
// @Param  family  query  []string  false  "family: any of (comma list)"  collectionFormat(csv)
// @Param  family_not  query  []string  false  "family: none of (comma list)"  collectionFormat(csv)
// @Param  finding_type  query  []string  false  "finding type: any of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3)
// @Param  finding_type_not  query  []string  false  "finding type: none of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3)
// @Param  is_in_kev  query  boolean  false  "is in kev equals"
// @Param  is_reachable  query  boolean  false  "is reachable equals"
// @Param  epss_score_gte  query  number  false  "epss score at least"
// @Param  epss_score_lte  query  number  false  "epss score at most"
// @Param  epss_score_gt  query  number  false  "epss score greater than"
// @Param  epss_score_lt  query  number  false  "epss score less than"
// @Param  tool_name  query  []string  false  "tool name: any of (comma list)"  collectionFormat(csv)
// @Param  tool_name_not  query  []string  false  "tool name: none of (comma list)"  collectionFormat(csv)
// @Param  rule_id  query  []string  false  "rule id: any of (comma list)"  collectionFormat(csv)
// @Param  rule_id_not  query  []string  false  "rule id: none of (comma list)"  collectionFormat(csv)
// @Param  scan_id  query  []string  false  "scan id: any of (comma list)"  collectionFormat(csv)
// @Param  scan_id_not  query  []string  false  "scan id: none of (comma list)"  collectionFormat(csv)
// @Param  file_path  query  string  false  "file path contains"
// @Param  file_path_contains  query  string  false  "file path contains"
// @Param  asset_tag  query  []string  false  "asset tag: any of (comma list)"  collectionFormat(csv)
// @Param  asset_tag_not  query  []string  false  "asset tag: none of (comma list)"  collectionFormat(csv)
// @Param  related_to  query  string  false  "related to equals"  Enums(me)
// @Param  cvss_score_gte  query  number  false  "cvss score at least"
// @Param  cvss_score_lte  query  number  false  "cvss score at most"
// @Param  cvss_score_gt  query  number  false  "cvss score greater than"
// @Param  cvss_score_lt  query  number  false  "cvss score less than"
// @Param  first_detected_at_gte  query  string  false  "first detected at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_lte  query  string  false  "first detected at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_gt  query  string  false  "first detected at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  first_detected_at_lt  query  string  false  "first detected at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gte  query  string  false  "last seen at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lte  query  string  false  "last seen at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_gt  query  string  false  "last seen at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  last_seen_at_lt  query  string  false  "last seen at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_gte  query  string  false  "resolved at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_lte  query  string  false  "resolved at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_gt  query  string  false  "resolved at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  resolved_at_lt  query  string  false  "resolved at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  network_port  query  []integer  false  "network port: any of (comma list)"  collectionFormat(csv)
// @Param  network_port_not  query  []integer  false  "network port: none of (comma list)"  collectionFormat(csv)
// @Param  network_port_gte  query  integer  false  "network port at least"
// @Param  network_port_lte  query  integer  false  "network port at most"
// @Param  network_transport  query  []string  false  "network transport: any of (comma list)"  collectionFormat(csv)  Enums(tcp, udp, sctp)
// @Param  network_transport_not  query  []string  false  "network transport: none of (comma list)"  collectionFormat(csv)  Enums(tcp, udp, sctp)
// @Param  network_service  query  []string  false  "network service: any of (comma list)"  collectionFormat(csv)
// @Param  network_service_not  query  []string  false  "network service: none of (comma list)"  collectionFormat(csv)
// @Param  assigned_to  query  []string  false  "assigned to: any of (comma list)"  collectionFormat(csv)
// @Param  assigned_to_null  query  boolean  false  "assigned to is unset (true) or set (false)"
// @Param  assigned_to_not  query  []string  false  "assigned to: none of (comma list)"  collectionFormat(csv)
// @Param  asset_criticality  query  []string  false  "asset criticality: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  asset_criticality_not  query  []string  false  "asset criticality: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low)
// @Param  asset_owner_id  query  []string  false  "asset owner id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_owner_id_null  query  boolean  false  "asset owner id is unset (true) or set (false)"
// @Param  exploit_available  query  boolean  false  "exploit available equals"
// @Param  created_at_gte  query  string  false  "created at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_lte  query  string  false  "created at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_gt  query  string  false  "created at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  created_at_lt  query  string  false  "created at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_gte  query  string  false  "updated at at least (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_lte  query  string  false  "updated at at most (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_gt  query  string  false  "updated at greater than (RFC 3339, YYYY-MM-DD, or -P30D)"
// @Param  updated_at_lt  query  string  false  "updated at less than (RFC 3339, YYYY-MM-DD, or -P30D)"
// end filterspec-params
// @Param        q      query  string  false  "Free text"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]interface{}  "INVALID_FILTER"
// @Router       /findings/related-cves/{cveId} [get]
func (h *FindingActionsHandler) GetRelatedCVEs(w http.ResponseWriter, r *http.Request) {
	cveID := chi.URLParam(r, "cveId")
	if cveID == "" {
		apierror.BadRequest("cveId is required").WriteJSON(w)
		return
	}
	route := h.findingGroupsRoute()
	route.Name = "GET /findings/related-cves"
	route.Options.Extra = nil
	q := r.URL.Query()
	if !rewriteBranchStatus(w, q) {
		return
	}
	spec, ok := route.ParseValues(w, r, q)
	if !ok {
		return
	}
	result, err := h.service.GetRelatedCVEsBySpec(r.Context(), filterCaller(r), cveID, spec)
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"source_cve":   cveID,
		"related_cves": result,
	})
}

// --- Fix Applied ---

// FixAppliedRequest is the request body for POST /api/v1/findings/actions/fix-applied
type FixAppliedRequest struct {
	Filter             FindingFilterRequest `json:"filter"`
	IncludeRelatedCVEs bool                 `json:"include_related_cves"`
	Note               string               `json:"note" validate:"max=5000"`
	Reference          string               `json:"reference" validate:"max=1000"`
}

// FindingFilterRequest is the filter in request body.
type FindingFilterRequest struct {
	CVEIDs    []string `json:"cve_ids" validate:"max=100,dive,max=255"`
	AssetTags []string `json:"asset_tags" validate:"max=100,dive,max=255"`
	AssetIDs  []string `json:"asset_ids" validate:"max=100,dive,uuid"`
}

// FixApplied handles POST /api/v1/findings/actions/fix-applied
func (h *FindingActionsHandler) FixApplied(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req FixAppliedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate input bounds
	if len(req.Filter.CVEIDs) > 100 {
		apierror.BadRequest("Maximum 100 CVE IDs allowed").WriteJSON(w)
		return
	}
	if len(req.Filter.AssetTags) > 100 {
		apierror.BadRequest("Maximum 100 asset tags allowed").WriteJSON(w)
		return
	}
	if len(req.Filter.AssetIDs) > 100 {
		apierror.BadRequest("Maximum 100 asset IDs allowed").WriteJSON(w)
		return
	}
	if len(req.Note) > 5000 {
		apierror.BadRequest("Note must be at most 5000 characters").WriteJSON(w)
		return
	}

	// Require a scoping filter. Without this guard an empty filter would match
	// every in_progress finding (bounded only by the 1000 cap) — the same
	// "ids or filter required" guard Verify/RejectFix use, adapted to this
	// filter-only action. This also turns the previously-dropped asset_ids
	// path (UI's asset-grouped "mark fixed") from a dangerous broad match into
	// a properly scoped one via WithAssetID below.
	if len(req.Filter.CVEIDs) == 0 && len(req.Filter.AssetTags) == 0 && len(req.Filter.AssetIDs) == 0 {
		apierror.BadRequest("filter (cve_ids, asset_tags, or asset_ids) is required").WriteJSON(w)
		return
	}

	filter := vulnerability.NewFindingFilter()
	if len(req.Filter.CVEIDs) > 0 {
		filter = filter.WithCVEIDs(req.Filter.CVEIDs)
	}
	if len(req.Filter.AssetTags) > 0 {
		filter = filter.WithAssetTags(req.Filter.AssetTags)
	}
	// The domain filter scopes to a single asset; the UI's asset-grouped action
	// sends exactly one asset_id. Use the first if provided.
	if len(req.Filter.AssetIDs) > 0 {
		assetID, err := shared.IDFromString(req.Filter.AssetIDs[0])
		if err != nil {
			apierror.BadRequest("Invalid asset_id").WriteJSON(w)
			return
		}
		filter = filter.WithAssetID(assetID)
	}

	input := finding.BulkFixAppliedInput{
		Filter:             filter,
		IncludeRelatedCVEs: req.IncludeRelatedCVEs,
		Note:               req.Note,
		Reference:          req.Reference,
	}

	result, err := h.service.BulkFixApplied(r.Context(), tenantID, userID.String(), input)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// --- Verify (by IDs or by filter) ---

// VerifyRequest supports both finding_ids and filter. At least one must be provided.
type VerifyRequest struct {
	FindingIDs []string              `json:"finding_ids" validate:"max=100,dive,uuid"` // verify specific findings
	Filter     *FindingFilterRequest `json:"filter"`                                   // verify all matching filter
	Note       string                `json:"note" validate:"max=5000"`
}

// Verify handles POST /api/v1/findings/actions/verify
func (h *FindingActionsHandler) Verify(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate input bounds
	if len(req.FindingIDs) > 100 {
		apierror.BadRequest("Maximum 100 finding IDs allowed").WriteJSON(w)
		return
	}
	if len(req.Note) > 5000 {
		apierror.BadRequest("Note must be at most 5000 characters").WriteJSON(w)
		return
	}
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 100 || len(req.Filter.AssetTags) > 100) {
		apierror.BadRequest("Maximum 100 filter items allowed").WriteJSON(w)
		return
	}

	// By filter (Pending Review tab uses this)
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 0 || len(req.Filter.AssetTags) > 0) {
		filter := vulnerability.NewFindingFilter()
		if len(req.Filter.CVEIDs) > 0 {
			filter = filter.WithCVEIDs(req.Filter.CVEIDs)
		}
		if len(req.Filter.AssetTags) > 0 {
			filter = filter.WithAssetTags(req.Filter.AssetTags)
		}
		count, err := h.service.BulkVerifyByFilter(r.Context(), tenantID, userID.String(), finding.VerifyByFilterInput{
			Filter: filter, Note: req.Note,
		})
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"updated": count})
		return
	}

	// By IDs
	if len(req.FindingIDs) == 0 {
		apierror.BadRequest("finding_ids or filter is required").WriteJSON(w)
		return
	}

	result, err := h.service.BulkVerify(r.Context(), tenantID, userID.String(), req.FindingIDs, req.Note)
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// --- Reject Fix (by IDs or by filter) ---

// RejectFixRequest supports both finding_ids and filter.
type RejectFixRequest struct {
	FindingIDs []string              `json:"finding_ids" validate:"max=100"`
	Filter     *FindingFilterRequest `json:"filter"`
	Reason     string                `json:"reason" validate:"max=5000"`
}

// RejectFix handles POST /api/v1/findings/actions/reject-fix
func (h *FindingActionsHandler) RejectFix(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req RejectFixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate input bounds
	if len(req.FindingIDs) > 100 {
		apierror.BadRequest("Maximum 100 finding IDs allowed").WriteJSON(w)
		return
	}
	if len(req.Reason) > 5000 {
		apierror.BadRequest("Reason must be at most 5000 characters").WriteJSON(w)
		return
	}
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 100 || len(req.Filter.AssetTags) > 100) {
		apierror.BadRequest("Maximum 100 filter items allowed").WriteJSON(w)
		return
	}

	// By filter
	if req.Filter != nil && (len(req.Filter.CVEIDs) > 0 || len(req.Filter.AssetTags) > 0) {
		filter := vulnerability.NewFindingFilter()
		if len(req.Filter.CVEIDs) > 0 {
			filter = filter.WithCVEIDs(req.Filter.CVEIDs)
		}
		if len(req.Filter.AssetTags) > 0 {
			filter = filter.WithAssetTags(req.Filter.AssetTags)
		}
		count, err := h.service.BulkRejectByFilter(r.Context(), tenantID, userID.String(), finding.RejectByFilterInput{
			Filter: filter, Reason: req.Reason,
		})
		if err != nil {
			h.handleError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"updated": count})
		return
	}

	// By IDs
	if len(req.FindingIDs) == 0 {
		apierror.BadRequest("finding_ids or filter is required").WriteJSON(w)
		return
	}

	result, err := h.service.BulkRejectFix(r.Context(), tenantID, userID.String(), req.FindingIDs, req.Reason)
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// RequestValidation handles POST /api/v1/findings/{id}/validate
// It dispatches a CTEM Stage-4 validation job (safe-check re-check) for the
// finding. The job runs on a sensor; the outcome is applied to the finding
// asynchronously when the sensor completes the command.
func (h *FindingActionsHandler) RequestValidation(w http.ResponseWriter, r *http.Request) {
	if h.validationRunner == nil {
		apierror.InternalServerError("validation is not configured").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		apierror.BadRequest("finding id is required").WriteJSON(w)
		return
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		apierror.BadRequest("invalid finding id").WriteJSON(w)
		return
	}

	cmdID, err := h.validationRunner.ValidateFinding(r.Context(), tid, fid)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusAccepted, map[string]any{
		"finding_id": findingID,
		"command_id": cmdID.String(),
		"status":     "queued",
	})
}

// --- Auto-Assign ---

// AssignToOwnersRequest is the request body for POST /api/v1/findings/actions/assign-to-owners
type AssignToOwnersRequest struct {
	Filter FindingFilterRequest `json:"filter"`
}

// AssignToOwners handles POST /api/v1/findings/actions/assign-to-owners
func (h *FindingActionsHandler) AssignToOwners(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetLocalUserID(r.Context())

	var req AssignToOwnersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	filter := vulnerability.NewFindingFilter()
	if len(req.Filter.CVEIDs) > 0 {
		filter = filter.WithCVEIDs(req.Filter.CVEIDs)
	}
	if len(req.Filter.AssetTags) > 0 {
		filter = filter.WithAssetTags(req.Filter.AssetTags)
	}

	result, err := h.service.AutoAssignToOwners(r.Context(), tenantID, userID.String(), filter)
	if err != nil {
		h.handleError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// --- Helpers ---

func (h *FindingActionsHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Finding").WriteJSON(w)
		return
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
		return
	}
	h.logger.Error("finding lifecycle error", "error", err)
	apierror.InternalServerError("Internal server error").WriteJSON(w)
}

func (h *FindingActionsHandler) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
