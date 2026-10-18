package handler

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
)

const (
	auditExportCSV   = "csv"
	auditExportJSONL = "jsonl"
)

// auditExportHeader is the column set of the export, in order.
var auditExportHeader = []string{
	"time", "action", "severity", "result", "actor_id", "actor_email",
	"resource_type", "resource_id", "resource_name", "ip", "request_id", "changes",
}

// auditExportLine is one JSON lines record: the CSV columns, with the changes
// as a JSON value.
type auditExportLine struct {
	Time         string         `json:"time"`
	Action       string         `json:"action"`
	Severity     string         `json:"severity"`
	Result       string         `json:"result"`
	ActorID      string         `json:"actor_id"`
	ActorEmail   string         `json:"actor_email"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceName string         `json:"resource_name"`
	IP           string         `json:"ip"`
	RequestID    string         `json:"request_id"`
	Changes      *audit.Changes `json:"changes,omitempty"`
}

func auditExportColumns(l *audit.AuditLog) auditExportLine {
	line := auditExportLine{
		Time:         l.Timestamp().UTC().Format(time.RFC3339),
		Action:       l.Action().String(),
		Severity:     l.Severity().String(),
		Result:       l.Result().String(),
		ActorEmail:   l.ActorEmail(),
		ResourceType: l.ResourceType().String(),
		ResourceID:   l.ResourceID(),
		ResourceName: l.ResourceName(),
		IP:           l.ActorIP(),
		RequestID:    l.RequestID(),
		Changes:      l.Changes(),
	}
	if l.ActorID() != nil {
		line.ActorID = l.ActorID().String()
	}
	return line
}

func auditExportCSVRow(l *audit.AuditLog) []string {
	c := auditExportColumns(l)
	changes := ""
	if c.Changes != nil {
		if b, err := json.Marshal(c.Changes); err == nil {
			changes = string(b)
		}
	}
	row := []string{c.Time, c.Action, c.Severity, c.Result, c.ActorID, c.ActorEmail,
		c.ResourceType, c.ResourceID, c.ResourceName, c.IP, c.RequestID, changes}
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return row
}

// Export handles GET /api/v1/audit-logs/export
// @Summary      Export audit logs
// @Description  Streams the organization's audit log as CSV or JSON lines, newest first, with the filters of the list, up to 50,000 rows (X-Export-Truncated: true when more match). The export is itself audit-logged.
// @Tags         Audit Logs
// @Produce      text/csv
// @Produce      application/x-ndjson
// @Security     BearerAuth
// @Param        format        query     string  false  "csv (default) or jsonl"
// @Param        actor_id      query     string  false  "Filter by actor ID"
// @Param        action        query     string  false  "Filter by action"
// @Param        resource_type query     string  false  "Filter by resource type"
// @Param        resource_id   query     string  false  "Filter by resource ID"
// @Param        result        query     string  false  "Filter by result"
// @Param        severity      query     string  false  "Filter by severity"
// @Param        request_id    query     string  false  "Filter by request ID"
// @Param        since         query     string  false  "Filter since (RFC3339)"
// @Param        until         query     string  false  "Filter until (RFC3339)"
// @Param        search        query     string  false  "Search term"
// @Param        exclude_system query    string  false  "true: leave out system events"
// @Success      200  {string}  string  "CSV or JSON lines stream"
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      429  {object}  map[string]string
// @Router       /audit-logs/export [get]
func (h *AuditHandler) Export(w http.ResponseWriter, r *http.Request) {
	if !h.requireFullData(w, r) {
		return
	}
	ctx := r.Context()
	tenantID := middleware.GetTenantID(ctx)
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	query := r.URL.Query()
	format := strings.ToLower(query.Get("format"))
	switch format {
	case "":
		format = auditExportCSV
	case auditExportCSV, auditExportJSONL:
	default:
		apierror.BadRequest("format must be csv or jsonl").WriteJSON(w)
		return
	}
	input := auditsvc.ListAuditLogsInput{TenantID: tenantID}
	parseAuditFilters(query, &input)
	var used []string
	for _, p := range auditFilterParams {
		if query.Get(p) != "" {
			used = append(used, p)
		}
	}

	// One export at a time per person, and the tenant's heavy-read cap on
	// the route, so a dump cannot tie up the database.
	slot := tenantID + ":" + middleware.GetUserID(ctx)
	if !acquireExportSlot(slot) {
		apierror.TooManyRequests("An export is already running for you; wait for it to finish").WriteJSON(w)
		return
	}
	defer releaseExportSlot(slot)

	truncated, err := h.service.ExportWouldTruncate(ctx, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	started := false
	var csvw *csv.Writer
	enc := json.NewEncoder(w)
	start := func() {
		started = true
		hdr := w.Header()
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Export-Max-Rows", strconv.Itoa(auditsvc.MaxExportRows))
		hdr.Set("X-Export-Truncated", strconv.FormatBool(truncated))
		hdr.Set("Access-Control-Expose-Headers", "X-Export-Truncated, X-Export-Max-Rows, Content-Disposition")
		name := "audit-log-" + h.exportOrgName(r) + "-" + time.Now().UTC().Format("20060102T150405Z")
		if format == auditExportCSV {
			hdr.Set("Content-Type", "text/csv; charset=utf-8")
			hdr.Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		} else {
			hdr.Set("Content-Type", "application/x-ndjson")
			hdr.Set("Content-Disposition", `attachment; filename="`+name+`.jsonl"`)
		}
		w.WriteHeader(http.StatusOK)
		if format == auditExportCSV {
			csvw = csv.NewWriter(w)
			_ = csvw.Write(auditExportHeader)
		}
	}
	emit := func(batch []*audit.AuditLog) error {
		if !started {
			start()
		}
		for _, l := range batch {
			var err error
			if format == auditExportCSV {
				err = csvw.Write(auditExportCSVRow(l))
			} else {
				err = enc.Encode(auditExportColumns(l))
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

	rows, err := h.service.ExportAuditLogs(ctx, input, emit)
	if err != nil && !started {
		h.handleServiceError(w, err)
		return
	}
	if !started {
		start() // an empty export still has its header row
	}
	if csvw != nil {
		csvw.Flush()
	}
	if format == auditExportJSONL && truncated && err == nil {
		_ = enc.Encode(map[string]bool{"truncated": true})
	}
	if err != nil {
		h.logger.Warn("audit log export ended early", "rows", rows, "error", err)
	}

	// Recorded after the stream, so the export does not list its own event;
	// the context is detached from a client that went away mid-stream.
	res := auditsvc.ExportResult{Rows: rows, Truncated: truncated}
	actx := auditsvc.AuditContext{
		TenantID:   tenantID,
		ActorID:    middleware.GetUserID(ctx),
		ActorEmail: auditActorEmail(ctx),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	if lerr := h.service.LogExport(ctx, actx, format, used, res, err != nil); lerr != nil {
		h.logger.Warn("audit log export event failed", "error", lerr)
	}
}

// exportOrgName is the organization part of the file name: the slug of the
// credential's organization, else the tenant id.
func (h *AuditHandler) exportOrgName(r *http.Request) string {
	if slug := safeFileToken(middleware.GetTeamSlug(r.Context())); slug != "" {
		return slug
	}
	return safeFileToken(middleware.GetTenantID(r.Context()))
}

// safeFileToken keeps letters, digits, dash and underscore.
func safeFileToken(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}
