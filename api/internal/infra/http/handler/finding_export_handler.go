package handler

// Server-side findings export (RFC-048 §3.6, research 17 R5): the filter is
// the list's (GET params or a FilterDocument), compiled as the caller, so an
// export can never contain a row the caller cannot list. Rows stream in id
// order in keyset batches, capped at finding.MaxExportRows; one export runs
// per user at a time; every export is audit-logged without filter values.
// CSV cells that a spreadsheet would run as a formula are neutralized.

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// exportSlots allows one running export per tenant and user on this API
// instance, so one caller cannot tie up the database with parallel dumps.
var exportSlots = struct {
	sync.Mutex
	busy map[string]bool
}{busy: map[string]bool{}}

func acquireExportSlot(key string) bool {
	exportSlots.Lock()
	defer exportSlots.Unlock()
	if exportSlots.busy[key] {
		return false
	}
	exportSlots.busy[key] = true
	return true
}

func releaseExportSlot(key string) {
	exportSlots.Lock()
	delete(exportSlots.busy, key)
	exportSlots.Unlock()
}

// findingCSVHeader is the column set of a CSV export. Snippets, secrets and
// free-form metadata are left out on purpose.
var findingCSVHeader = []string{
	"id", "title", "severity", "status", "priority_class", "source", "finding_type", "tool_name", "rule_id",
	"cve_id", "cvss_score", "epss_score", "is_in_kev", "sla_status", "asset_id", "asset_name", "file_path",
	"start_line", "network_port", "network_service", "assigned_to", "first_detected_at", "last_seen_at", "created_at",
}

// csvSafe neutralizes a cell a spreadsheet would evaluate as a formula
// (OWASP CSV injection): a leading = + - @ tab or carriage return gets a
// leading apostrophe.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func findingCSVRow(f FindingResponse) []string {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
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
	assetName := ""
	if f.Asset != nil {
		assetName = f.Asset.Name
	}
	title := f.Title
	if title == "" {
		title = f.Message
	}
	row := []string{
		f.ID, title, f.Severity, f.Status, str(f.PriorityClass), f.Source, f.FindingType, f.ToolName, f.RuleID,
		f.CVEID, num(f.CVSSScore), num(f.EPSSScore), strconv.FormatBool(f.IsInKEV), f.SLAStatus, f.AssetID, assetName, f.FilePath,
		intOrEmpty(f.StartLine), intOrEmpty(f.NetworkPort), f.NetworkService, str(f.AssignedTo),
		ts(f.FirstDetectedAt), ts(f.LastSeenAt), ts(f.CreatedAt),
	}
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return row
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
// @Description  in id order, at most 100,000 rows; the X-Export-Truncated trailer says whether rows were left
// @Description  out. Same scope as GET /findings. Needs findings:export. One export per user at a time (429
// @Description  otherwise). Audit-logged without filter values. CSV formula cells are neutralized.
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
// @Param  component_id  query  []string  false  "component id: any of (comma list)"  collectionFormat(csv)
// @Param  component_id_not  query  []string  false  "component id: none of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id  query  []string  false  "vulnerability id: any of (comma list)"  collectionFormat(csv)
// @Param  vulnerability_id_not  query  []string  false  "vulnerability id: none of (comma list)"  collectionFormat(csv)
// @Param  severity  query  []string  false  "severity: any of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  severity_not  query  []string  false  "severity: none of (comma list)"  collectionFormat(csv)  Enums(critical, high, medium, low, info, none)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate, draft, in_review, remediation, retest, verified, accepted_risk)
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
// @Param        q       query  string  false  "Free text"
// @Success      200  {string}  string  "CSV or NDJSON stream"
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

	caller := filterCaller(r)
	slot := caller.TenantID + ":" + caller.UserID
	if !acquireExportSlot(slot) {
		apierror.TooManyRequests("An export is already running for you; wait for it to finish").WriteJSON(w)
		return
	}
	defer releaseExportSlot(slot)

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
		hdr.Set("X-Export-Max-Rows", strconv.Itoa(app.MaxExportRows))
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
			_ = csvw.Write(findingCSVHeader)
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
			var err error
			if format == exportFormatCSV {
				err = csvw.Write(findingCSVRow(f))
			} else {
				err = enc.Encode(f)
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

	res, err := h.service.ExportFindingsBySpec(ctx, caller, spec, format, h.exportAuditContext(r), emit)
	if err != nil && !started {
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
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
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}
