package handler

// Server-side findings export (RFC-048 §3.6, research 17 R5, research 234
// D10): the filter is the list's (GET params or a FilterDocument), parsed
// strictly and compiled as the caller, so an export can never contain a row
// the caller cannot list. Rows come in the list's sort, from one database
// snapshot, capped at finding.MaxExportRows; one export runs per user at a
// time across replicas; every export is audit-logged without filter values.
// Each row is the FindingExportRow allowlist: no evidence, code snippets,
// stack traces, fix code, metadata or secret details ever leave this way.
// CSV cells that a spreadsheet would run as a formula are neutralized.

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// FindingExportRow is the allowlist of what a findings export carries, in
// CSV column order. A field is added here only by decision: an export leaves
// the platform's access control, so evidence (snippets, scanner output,
// stack traces, attachments, data flow), fix code, free-form metadata,
// descriptions and every secret detail stay out.
// TestFindingExportRow_EveryResponseFieldDecided fails when FindingResponse
// gains a field that is neither exported nor excluded here.
type FindingExportRow struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	DisplayTitle     string     `json:"display_title"` // "<title> on <target>"; the asset is also its own columns
	Severity         string     `json:"severity"`
	Status           string     `json:"status"`
	PriorityClass    string     `json:"priority_class"`
	Source           string     `json:"source"`
	FindingType      string     `json:"finding_type"`
	ToolName         string     `json:"tool_name"`
	RuleID           string     `json:"rule_id"`
	RuleName         string     `json:"rule_name"`
	CVEID            string     `json:"cve_id"`
	CVEIDs           []string   `json:"cve_ids"`
	CWEIDs           []string   `json:"cwe_ids"`
	CVSSScore        *float64   `json:"cvss_score"`
	CVSSVector       string     `json:"cvss_vector"`
	EPSSScore        *float64   `json:"epss_score"`
	EPSSPercentile   *float64   `json:"epss_percentile"`
	IsInKEV          bool       `json:"is_in_kev"`
	ExploitAvailable bool       `json:"exploit_available"`
	IsReachable      bool       `json:"is_reachable"`
	SLAStatus        string     `json:"sla_status"`
	SLADeadline      *time.Time `json:"sla_deadline"`
	AssetID          string     `json:"asset_id"`
	AssetName        string     `json:"asset_name"`
	AssetType        string     `json:"asset_type"`
	FilePath         string     `json:"file_path"`
	StartLine        int        `json:"start_line"`
	EndLine          int        `json:"end_line"`
	NetworkPort      int        `json:"network_port"`
	NetworkTransport string     `json:"network_transport"`
	NetworkService   string     `json:"network_service"`
	Family           string     `json:"family"`
	AssignedTo       string     `json:"assigned_to"`
	Observation      string     `json:"observation"`
	Validation       string     `json:"validation"`
	FirstDetectedAt  time.Time  `json:"first_detected_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	ResolvedAt       *time.Time `json:"resolved_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// findingExportColumns are FindingExportRow's json names in field order: the
// CSV header.
var findingExportColumns = func() []string {
	t := reflect.TypeOf(FindingExportRow{})
	out := make([]string, t.NumField())
	for i := range out {
		out[i] = strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
	}
	return out
}()

// toFindingExportRow copies the allowlisted fields of an enriched response.
func toFindingExportRow(f FindingResponse) FindingExportRow {
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	title := f.Title
	if title == "" {
		title = f.Message
	}
	row := FindingExportRow{
		ID: f.ID, Title: title, DisplayTitle: f.DisplayTitle, Severity: f.Severity, Status: f.Status, PriorityClass: deref(f.PriorityClass),
		Source: f.Source, FindingType: f.FindingType, ToolName: f.ToolName, RuleID: f.RuleID, RuleName: f.RuleName,
		CVEID: f.CVEID, CVEIDs: f.CVEIDs, CWEIDs: f.CWEIDs, CVSSScore: f.CVSSScore, CVSSVector: f.CVSSVector,
		EPSSScore: f.EPSSScore, EPSSPercentile: f.EPSSPercentile, IsInKEV: f.IsInKEV,
		ExploitAvailable: f.ExploitAvailable, IsReachable: f.IsReachable,
		SLAStatus: f.SLAStatus, SLADeadline: f.SLADeadline, AssetID: f.AssetID,
		FilePath: f.FilePath, StartLine: f.StartLine, EndLine: f.EndLine,
		NetworkPort: f.NetworkPort, NetworkTransport: f.NetworkTransport, NetworkService: f.NetworkService,
		Family: f.Family, AssignedTo: deref(f.AssignedTo), Observation: f.Observation, Validation: f.Validation,
		FirstDetectedAt: f.FirstDetectedAt, LastSeenAt: f.LastSeenAt, ResolvedAt: f.ResolvedAt,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
	if f.Asset != nil {
		row.AssetName, row.AssetType = f.Asset.Name, f.Asset.Type
	}
	return row
}

// csvSafe neutralizes a cell a spreadsheet would evaluate as a formula
// (OWASP CSV injection). It is sanitizeCSVCell, the one rule every CSV
// export uses: a leading tab or carriage return, or = + - @ after any
// leading whitespace (" =HYPERLINK(...)" is still a formula), gets a
// leading apostrophe.
func csvSafe(s string) string { return sanitizeCSVCell(s) }

// csvCells renders a row in findingExportColumns order. Lists are joined
// with ";", times are RFC 3339 UTC, zero numbers and unset values are empty.
func (row FindingExportRow) csvCells() []string {
	num := func(p *float64) string {
		if p == nil {
			return ""
		}
		return strconv.FormatFloat(*p, 'f', -1, 64)
	}
	intOrEmpty := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	tsp := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return ts(*t)
	}
	cells := []string{
		row.ID, row.Title, row.DisplayTitle, row.Severity, row.Status, row.PriorityClass, row.Source, row.FindingType, row.ToolName,
		row.RuleID, row.RuleName, row.CVEID, strings.Join(row.CVEIDs, ";"), strings.Join(row.CWEIDs, ";"),
		num(row.CVSSScore), row.CVSSVector, num(row.EPSSScore), num(row.EPSSPercentile),
		strconv.FormatBool(row.IsInKEV), strconv.FormatBool(row.ExploitAvailable), strconv.FormatBool(row.IsReachable),
		row.SLAStatus, tsp(row.SLADeadline), row.AssetID, row.AssetName, row.AssetType, row.FilePath,
		intOrEmpty(row.StartLine), intOrEmpty(row.EndLine), intOrEmpty(row.NetworkPort), row.NetworkTransport,
		row.NetworkService, row.Family, row.AssignedTo, row.Observation, row.Validation,
		ts(row.FirstDetectedAt), ts(row.LastSeenAt), tsp(row.ResolvedAt), ts(row.CreatedAt), ts(row.UpdatedAt),
	}
	for i := range cells {
		cells[i] = csvSafe(cells[i])
	}
	return cells
}

// ExportFindingsDocument handles POST /api/v1/findings/export
// @Summary      Export findings selected by a filter document
// @Description  POST /findings/search's FilterDocument body, streamed like GET /findings/export.
// @Tags         Findings
// @Accept       json
// @Produce      text/csv
// @Produce      application/x-ndjson
// @Security     BearerAuth
// @Param        format   query  string                false  "csv (default) or ndjson"  Enums(csv, ndjson)
// @Param        request  body   FindingSearchRequest  true   "Filter document"
// @Success      200  {string}  string  "CSV or NDJSON stream"
// @Failure      400  {object}  map[string]interface{}  "INVALID_FILTER"
// @Failure      429  {object}  map[string]interface{}
// @Router       /findings/export [post]
func (h *VulnerabilityHandler) ExportFindingsDocument(w http.ResponseWriter, r *http.Request) {
	h.ExportFindings(w, r)
}

// ExportFindings handles GET /api/v1/findings/export (and the POST form)
// @Summary      Export findings
// @Description  Streams every finding the list's filter selects as CSV (default) or NDJSON (`format=ndjson`),
// @Description  in the list's sort (`sort`, default priority), at most 10,000 rows; the X-Export-Max-Rows header
// @Description  gives the cap and the X-Export-Truncated trailer says whether rows were left out (narrow the filter;
// @Description  larger exports are not offered yet). Same scope as GET /findings. Unknown params are 400
// @Description  INVALID_FILTER. Each row has the export allowlist only: no evidence, snippets, stack traces, fix
// @Description  code, metadata or secret details. Needs findings:export (403 names it). One export per user at a
// @Description  time across replicas (429 otherwise). Audit-logged without filter values. CSV formula cells are
// @Description  neutralized.
// @Tags         Findings
// @Produce      text/csv
// @Produce      application/x-ndjson
// @Security     BearerAuth
// @Param        format  query  string  false  "csv (default) or ndjson"  Enums(csv, ndjson)
// filterspec-params: findings GET /findings/export
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
// @Param  file_path  query  string  false  "file path contains"
// @Param  file_path_contains  query  string  false  "file path contains"
// @Param  description  query  string  false  "description contains"
// @Param  description_contains  query  string  false  "description contains"
// @Param  asset_tag  query  []string  false  "asset tag: any of (comma list)"  collectionFormat(csv)
// @Param  asset_tag_not  query  []string  false  "asset tag: none of (comma list)"  collectionFormat(csv)
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
// @Param        q       query  string  false  "Matches title, file path, rule id, CVE id (exact) and asset name"
// @Param        sort    query  string  false  "The list's sort keys, e.g. -cvss_score,severity"
// @Success      200  {string}  string  "CSV or NDJSON stream"
// @Failure      403  {object}  map[string]interface{}  "missing findings:export"
// @Failure      400  {object}  map[string]interface{}  "INVALID_FILTER"
// @Failure      429  {object}  map[string]interface{}
// @Router       /findings/export [get]
func (h *VulnerabilityHandler) ExportFindings(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	switch format {
	case "":
		format = exportFormatCSV
	case exportFormatCSV, "ndjson":
	default:
		filterquery.WriteError(w, &filterspec.Error{Details: []filterspec.Detail{{Param: "format", Reason: "must be csv or ndjson", Value: format}}})
		return
	}

	route := h.findingsListRoute()
	route.Name = "GET /findings/export"
	// An export is strict for every caller: an unknown param is a 400, never
	// a silently wider export.
	route.Options.Unknown = filterspec.UnknownStrict
	route.Options.Extra = append(route.Options.Extra, "format")
	var spec *filterspec.Spec
	var ok bool
	if r.Method == http.MethodPost {
		route.Name = "POST /findings/export"
		spec, ok = route.ParseBody(w, r)
	} else {
		q := r.URL.Query()
		if !rewriteBranchStatus(w, q) {
			return
		}
		spec, ok = route.ParseValues(w, r, q)
	}
	if !ok {
		return
	}
	if spec, ok = applySavedView(h.savedViews, savedview.PageFindings, w, r, spec); !ok {
		return
	}

	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	started := false
	var csvw *csv.Writer
	enc := json.NewEncoder(w)
	start := func() {
		started = true
		hdr := w.Header()
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Trailer", "X-Export-Truncated, X-Export-Rows")
		hdr.Set("X-Export-Max-Rows", strconv.Itoa(finding.MaxExportRows))
		name := "findings-" + time.Now().UTC().Format("20060102-150405")
		if format == exportFormatCSV {
			hdr.Set("Content-Type", "text/csv; charset=utf-8")
			hdr.Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		} else {
			hdr.Set("Content-Type", "application/x-ndjson")
			hdr.Set("Content-Disposition", `attachment; filename="`+name+`.ndjson"`)
		}
		w.WriteHeader(http.StatusOK)
		if format == exportFormatCSV {
			csvw = csv.NewWriter(w)
			_ = csvw.Write(findingExportColumns)
		}
	}
	emit := func(batch []*vulnerability.Finding) error {
		if !started {
			start()
		}
		data := make([]FindingResponse, len(batch))
		for i, f := range batch {
			data[i] = toFindingResponse(f)
		}
		h.enrichFindingsWithAssetInfo(ctx, tenantID, data)
		for _, f := range data {
			row := toFindingExportRow(f)
			var err error
			if format == exportFormatCSV {
				err = csvw.Write(row.csvCells())
			} else {
				err = enc.Encode(row)
			}
			if err != nil {
				return err
			}
		}
		if csvw != nil {
			csvw.Flush()
			if err := csvw.Error(); err != nil {
				return err
			}
		}
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		return nil
	}

	res, err := h.service.ExportFindingsBySpec(ctx, filterCaller(r), spec, format, h.exportAuditContext(r), emit)
	if err != nil && !started {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		if errors.Is(err, vulnerability.ErrExportInProgress) {
			apierror.TooManyRequests("An export is already running for you; wait for it to finish").WriteJSON(w)
			return
		}
		h.handleServiceError(w, err, "Finding")
		return
	}
	if !started {
		start() // an empty export still has its header row
	}
	if csvw != nil {
		csvw.Flush()
	}
	w.Header().Set("X-Export-Rows", strconv.Itoa(res.Rows))
	w.Header().Set("X-Export-Truncated", strconv.FormatBool(res.Truncated))
	if err != nil {
		h.logger.Warn("findings export ended early", "rows", res.Rows, "error", err)
	}
}

// exportAuditContext is the audit context of an export request.
func (h *VulnerabilityHandler) exportAuditContext(r *http.Request) auditapp.AuditContext {
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
	}
}
