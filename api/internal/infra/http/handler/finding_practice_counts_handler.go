package handler

// Practice counts of the findings list's practice switch
// (docs/architecture/finding-practices.md).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingPracticeCountResponse is one practice with the caller's count.
type FindingPracticeCountResponse struct {
	// Practice: aspm, infra, external, cloud, compliance, offensive,
	// identity, runtime or other.
	Practice string `json:"practice"`
	Count    int64  `json:"count"`
}

// FindingPracticeCountsResponse is the response of GET /findings/practice-counts.
type FindingPracticeCountsResponse struct {
	// Total is every finding the filter selects, whatever its practice.
	Total int64 `json:"total"`
	// Vulnerabilities is every practice except compliance (the list's default).
	Vulnerabilities int64 `json:"vulnerabilities"`
	// Practices lists every practice in display order, with its count.
	Practices []FindingPracticeCountResponse `json:"practices"`
	AsOf      time.Time                      `json:"as_of"`
}

// FindingPracticeCounts handles GET /api/v1/findings/practice-counts
// @Summary      Findings per practice
// @Description  The caller's findings per practice under the same filter params as GET /findings, with any practice
// @Description  condition left out: the counts beside the findings list's practice switch. Each count is the total
// @Description  GET /findings returns to the same caller with that practice (tenant, data scope and pentest
// @Description  membership applied). One statement, 5 s limit (503 when it runs out).
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// filterspec-params: findings GET /findings/practice-counts
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
// @Param  informational  query  boolean  false  "informational equals"
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, resolved, false_positive, accepted, duplicate, draft, in_review)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, resolved, false_positive, accepted, duplicate, draft, in_review)
// @Param  observation  query  []string  false  "observation: any of (comma list)"  collectionFormat(csv)  Enums(present, stale)
// @Param  observation_not  query  []string  false  "observation: none of (comma list)"  collectionFormat(csv)  Enums(present, stale)
// @Param  validation  query  []string  false  "validation: any of (comma list)"  collectionFormat(csv)  Enums(reproducible, not_reproducible)
// @Param  validation_not  query  []string  false  "validation: none of (comma list)"  collectionFormat(csv)  Enums(reproducible, not_reproducible)
// @Param  state  query  string  false  "state equals"  Enums(open, fixed, dispositioned, closed, all)
// @Param  source  query  []string  false  "source: any of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  source_not  query  []string  false  "source: none of (comma list)"  collectionFormat(csv)  Enums(sast, dast, sca, secret, iac, container, cspm, easm, va, rasp, waf, siem, manual, pentest, bug_bounty, red_team, external, threat_intel, vendor, sarif, sca_tool)
// @Param  sla_status  query  []string  false  "sla status: any of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  sla_status_not  query  []string  false  "sla status: none of (comma list)"  collectionFormat(csv)  Enums(on_track, warning, overdue, exceeded, not_applicable)
// @Param  priority_class  query  []string  false  "priority class: any of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  priority_class_not  query  []string  false  "priority class: none of (comma list)"  collectionFormat(csv)  Enums(P0, P1, P2, P3)
// @Param  cve_id  query  []string  false  "cve id: any of (comma list)"  collectionFormat(csv)
// @Param  cve_id_null  query  boolean  false  "cve id is unset (true) or set (false)"
// @Param  cve_id_not  query  []string  false  "cve id: none of (comma list)"  collectionFormat(csv)
// @Param  family  query  []string  false  "family: any of (comma list)"  collectionFormat(csv)
// @Param  family_not  query  []string  false  "family: none of (comma list)"  collectionFormat(csv)
// @Param  finding_type  query  []string  false  "finding type: any of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3, license)
// @Param  finding_type_not  query  []string  false  "finding type: none of (comma list)"  collectionFormat(csv)  Enums(vulnerability, secret, misconfiguration, compliance, web3, license)
// @Param  practice  query  []string  false  "practice: any of (comma list)"  collectionFormat(csv)  Enums(aspm, infra, external, cloud, compliance, offensive, identity, runtime, other)
// @Param  practice_not  query  []string  false  "practice: none of (comma list)"  collectionFormat(csv)  Enums(aspm, infra, external, cloud, compliance, offensive, identity, runtime, other)
// @Param  compliance_result  query  []string  false  "compliance result: any of (comma list)"  collectionFormat(csv)  Enums(pass, fail, manual, not_applicable, error, unknown)
// @Param  compliance_result_not  query  []string  false  "compliance result: none of (comma list)"  collectionFormat(csv)  Enums(pass, fail, manual, not_applicable, error, unknown)
// @Param  is_in_kev  query  boolean  false  "is in kev equals"
// @Param  kev_ransomware  query  boolean  false  "kev ransomware equals"
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
// @Param  seen_by_sensor_id  query  []string  false  "seen by sensor id: any of (comma list)"  collectionFormat(csv)
// @Param  seen_by_scan_id  query  []string  false  "seen by scan id: any of (comma list)"  collectionFormat(csv)
// @Param  seen_in_run_id  query  []string  false  "seen in run id: any of (comma list)"  collectionFormat(csv)
// @Param  seen_by_tool  query  []string  false  "seen by tool: any of (comma list)"  collectionFormat(csv)
// @Param  seen_by_channel  query  []string  false  "seen by channel: any of (comma list)"  collectionFormat(csv)  Enums(scan, task, sensor, upload, ci, connector, platform, unknown)
// @Param  file_path  query  string  false  "file path contains"
// @Param  file_path_contains  query  string  false  "file path contains"
// @Param  description  query  string  false  "description contains"
// @Param  description_contains  query  string  false  "description contains"
// @Param  asset_tag  query  []string  false  "asset tag: any of (comma list)"  collectionFormat(csv)
// @Param  asset_tag_not  query  []string  false  "asset tag: none of (comma list)"  collectionFormat(csv)
// @Param  asset_type  query  []string  false  "asset type: any of (comma list)"  collectionFormat(csv)  Enums(domain, subdomain, ip_address, certificate, service, application, host, cloud_account, container, kubernetes, repository, identity, database, storage, network, unclassified)
// @Param  asset_type_not  query  []string  false  "asset type: none of (comma list)"  collectionFormat(csv)  Enums(domain, subdomain, ip_address, certificate, service, application, host, cloud_account, container, kubernetes, repository, identity, database, storage, network, unclassified)
// @Param  asset_domain  query  []string  false  "asset domain (example.com: the name and every asset under it; *.example.com: only under it): any of (comma list)"  collectionFormat(csv)
// @Param  asset_domain_not  query  []string  false  "asset domain (example.com: the name and every asset under it; *.example.com: only under it): none of (comma list)"  collectionFormat(csv)
// @Param  asset_name  query  []string  false  "asset name pattern (* any characters, ? one; at most 3 wildcards): any of (comma list)"  collectionFormat(csv)
// @Param  asset_name_not  query  []string  false  "asset name pattern (* any characters, ? one; at most 3 wildcards): none of (comma list)"  collectionFormat(csv)
// @Param  asset_group_id  query  []string  false  "asset group id: any of (comma list)"  collectionFormat(csv)
// @Param  related_to  query  string  false  "related to equals"  Enums(me, my_team)
// @Param  cvss_score_gte  query  number  false  "cvss score at least"
// @Param  cvss_score_lte  query  number  false  "cvss score at most"
// @Param  cvss_score_gt  query  number  false  "cvss score greater than"
// @Param  cvss_score_lt  query  number  false  "cvss score less than"
// @Param  first_detected_at_gte  query  string  false  "first detected at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_detected_at_lte  query  string  false  "first detected at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_detected_at_gt  query  string  false  "first detected at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  first_detected_at_lt  query  string  false  "first detected at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  sla_deadline_gte  query  string  false  "sla deadline at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  sla_deadline_lte  query  string  false  "sla deadline at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  sla_deadline_gt  query  string  false  "sla deadline greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  sla_deadline_lt  query  string  false  "sla deadline less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_at_gte  query  string  false  "last seen at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_at_lte  query  string  false  "last seen at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_at_gt  query  string  false  "last seen at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_seen_at_lt  query  string  false  "last seen at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  resolved_at_gte  query  string  false  "resolved at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  resolved_at_lte  query  string  false  "resolved at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  resolved_at_gt  query  string  false  "resolved at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  resolved_at_lt  query  string  false  "resolved at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  resolved_by_null  query  boolean  false  "resolved by is unset (true) or set (false)"
// @Param  last_reopened_at_gte  query  string  false  "last reopened at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_reopened_at_lte  query  string  false  "last reopened at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_reopened_at_gt  query  string  false  "last reopened at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_reopened_at_lt  query  string  false  "last reopened at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
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
// @Param  asset_criticality  query  []string  false  "asset criticality: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, none)
// @Param  asset_criticality_not  query  []string  false  "asset criticality: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, none)
// @Param  asset_crown_jewel  query  boolean  false  "asset crown jewel equals"
// @Param  asset_owner_id  query  []string  false  "asset owner id: any of (comma list)"  collectionFormat(csv)
// @Param  asset_owner_id_null  query  boolean  false  "asset owner id is unset (true) or set (false)"
// @Param  exploit_available  query  boolean  false  "exploit available equals"
// @Param  pending_approval  query  boolean  false  "pending approval equals"
// @Param  acceptance_expires_at_gte  query  string  false  "acceptance expires at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  acceptance_expires_at_lte  query  string  false  "acceptance expires at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  acceptance_expires_at_gt  query  string  false  "acceptance expires at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  acceptance_expires_at_lt  query  string  false  "acceptance expires at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_gte  query  string  false  "created at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_lte  query  string  false  "created at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_gt  query  string  false  "created at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_lt  query  string  false  "created at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  updated_at_gte  query  string  false  "updated at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  updated_at_lte  query  string  false  "updated at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  updated_at_gt  query  string  false  "updated at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  updated_at_lt  query  string  false  "updated at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// end filterspec-params
// @Param        view   query  string  false  "Saved view ID: its filter, with the other params overriding it field by field"
// @Param        q      query  string  false  "Matches title, file path, rule id, CVE id (exact) and asset name"
// @Success      200  {object}  FindingPracticeCountsResponse
// @Failure      400  {object}  apierror.Response
// @Failure      401  {object}  apierror.Response
// @Failure      403  {object}  apierror.Response
// @Failure      503  {object}  apierror.Response
// @Router       /findings/practice-counts [get]
func (h *VulnerabilityHandler) FindingPracticeCounts(w http.ResponseWriter, r *http.Request) {
	route := h.findingsListRoute()
	route.Name = "GET /findings/practice-counts"
	q := r.URL.Query()
	if !rewriteBranchStatus(w, q) {
		return
	}
	spec, ok := route.ParseValues(w, r, q)
	if !ok {
		return
	}
	if spec, ok = applySavedView(h.savedViews, savedview.PageFindings, w, r, spec); !ok {
		return
	}
	counts, err := h.service.CountPractices(r.Context(), filterCaller(r), spec)
	if err != nil {
		if errors.Is(err, vulnerability.ErrFindingCountTimeout) {
			apierror.ServiceUnavailable("Counting findings took too long; try again shortly").WriteJSON(w)
			return
		}
		h.logger.Error("failed to count findings per practice", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	resp := FindingPracticeCountsResponse{Total: counts.Total, AsOf: time.Now().UTC()}
	for _, p := range vulnerability.AllPractices() {
		n := counts.ByPractice[p]
		resp.Practices = append(resp.Practices, FindingPracticeCountResponse{Practice: p.String(), Count: n})
		if p != vulnerability.PracticeCompliance {
			resp.Vulnerabilities += n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=30")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
