package handler

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// exportAuditRepo serves a fixed list in batches, or an endless supply of
// rows when endless is set (to exercise the cap), and records the filters.
type exportAuditRepo struct {
	fakeAuditRepo
	rows    []*auditdom.AuditLog
	endless bool
	more    bool
	filters []auditdom.Filter
	batches int
}

func (m *exportAuditRepo) ExportBatch(_ context.Context, f auditdom.Filter, after *auditdom.ExportCursor, limit int) ([]*auditdom.AuditLog, error) {
	m.filters = append(m.filters, f)
	m.batches++
	if m.endless {
		out := make([]*auditdom.AuditLog, limit)
		for i := range out {
			out[i] = exportTestRow("row", "")
		}
		return out, nil
	}
	if after != nil {
		return nil, nil
	}
	return m.rows, nil
}

func (m *exportAuditRepo) HasMoreThan(_ context.Context, f auditdom.Filter, _ int) (bool, error) {
	m.filters = append(m.filters, f)
	return m.more, nil
}

func exportTestRow(name, changesField string) *auditdom.AuditLog {
	l, _ := auditdom.NewAuditLog(auditdom.ActionSettingsUpdated, auditdom.ResourceTypeSettings, "res-1", auditdom.ResultSuccess)
	l.WithActor(shared.NewID(), "who@example.com").WithResourceName(name).WithActorIP("192.0.2.7").WithRequestID("req-1")
	if changesField != "" {
		c := auditdom.NewChanges()
		c.After["field"] = changesField
		l.WithChanges(c)
	}
	return l
}

func exportRequest(h *AuditHandler, target string, admin bool, tenant string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	rec := httptest.NewRecorder()
	h.Export(rec, req.WithContext(ctx))
	return rec
}

func newExportHandler(repo *exportAuditRepo) *AuditHandler {
	return NewAuditHandler(auditsvc.NewAuditService(repo, logger.NewNop()), nil, logger.NewNop())
}

func TestAuditExport_CSVColumnsAndFormulaNeutralised(t *testing.T) {
	tenant := shared.NewID().String()
	repo := &exportAuditRepo{rows: []*auditdom.AuditLog{
		exportTestRow("=HYPERLINK(\"http://x\")", "+cmd"),
		exportTestRow("-1+1", ""),
		exportTestRow("@SUM(A1)", ""),
		exportTestRow("\tTab", ""),
		exportTestRow("\rCR", ""),
		exportTestRow("fine, with comma", ""),
	}}
	rec := exportRequest(newExportHandler(repo), "/api/v1/audit-logs/export?format=csv", true, tenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type %q", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="audit-log-`+tenant+`-`) || !strings.HasSuffix(cd, `Z.csv"`) {
		t.Fatalf("content disposition %q", cd)
	}
	if rec.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("truncated header %q", rec.Header().Get("X-Export-Truncated"))
	}
	recs, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if strings.Join(recs[0], ",") != strings.Join(auditExportHeader, ",") {
		t.Fatalf("header %v", recs[0])
	}
	if len(recs) != 7 {
		t.Fatalf("%d records", len(recs))
	}
	name := func(i int) string { return recs[i][8] }
	for i, want := range []string{`'=HYPERLINK("http://x")`, "'-1+1", "'@SUM(A1)", "'\tTab", "'\rCR", "fine, with comma"} {
		if got := name(i + 1); got != want {
			t.Errorf("row %d resource_name %q, want %q", i+1, got, want)
		}
	}
	first := recs[1]
	if _, err := time.Parse(time.RFC3339, first[0]); err != nil {
		t.Errorf("time %q is not RFC3339", first[0])
	}
	if first[1] != "settings.updated" || first[5] != "who@example.com" || first[9] != "192.0.2.7" || first[10] != "req-1" {
		t.Errorf("columns %v", first)
	}
	var ch map[string]map[string]any
	if err := json.Unmarshal([]byte(first[11]), &ch); err != nil || ch["after"]["field"] != "+cmd" {
		// the value is data inside a JSON string, which starts with "{"
		t.Errorf("changes column %q: %v", first[11], err)
	}
}

func TestAuditExport_JSONLAndTruncationMarker(t *testing.T) {
	repo := &exportAuditRepo{rows: []*auditdom.AuditLog{exportTestRow("one", "x"), exportTestRow("two", "")}, more: true}
	rec := exportRequest(newExportHandler(repo), "/api/v1/audit-logs/export?format=jsonl", true, shared.NewID().String())
	if rec.Code != http.StatusOK || rec.Header().Get("X-Export-Truncated") != "true" {
		t.Fatalf("status %d truncated %q", rec.Code, rec.Header().Get("X-Export-Truncated"))
	}
	if !strings.HasSuffix(rec.Header().Get("Content-Disposition"), `Z.jsonl"`) {
		t.Fatalf("filename %q", rec.Header().Get("Content-Disposition"))
	}
	var lines []string
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 3 || lines[2] != `{"truncated":true}` {
		t.Fatalf("lines %v", lines)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["resource_name"] != "one" || first["action"] != "settings.updated" {
		t.Fatalf("first line %v %v", first, err)
	}
}

func TestAuditExport_HardCap(t *testing.T) {
	repo := &exportAuditRepo{endless: true, more: true}
	rec := exportRequest(newExportHandler(repo), "/api/v1/audit-logs/export?format=jsonl", true, shared.NewID().String())
	if rec.Header().Get("X-Export-Truncated") != "true" {
		t.Fatal("a capped export must say so before the body")
	}
	n := strings.Count(rec.Body.String(), "\n")
	if n != auditsvc.MaxExportRows+1 { // rows + the truncation marker
		t.Fatalf("%d lines, want %d", n, auditsvc.MaxExportRows+1)
	}
}

func TestAuditExport_FiltersAndTenantAreApplied(t *testing.T) {
	tenant := shared.NewID().String()
	actor := shared.NewID().String()
	repo := &exportAuditRepo{}
	target := "/api/v1/audit-logs/export?actor_id=" + actor + "&action=settings.updated&action=auth.login&resource_type=settings&" +
		"resource_id=res-1&result=success&severity=high&request_id=req-9&since=2026-01-01T00:00:00Z&until=2026-02-01T00:00:00Z&search=hello&exclude_system=true"
	rec := exportRequest(newExportHandler(repo), target, true, tenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(repo.filters) == 0 {
		t.Fatal("repository not called")
	}
	for _, f := range repo.filters {
		if f.TenantID == nil || f.TenantID.String() != tenant {
			t.Fatalf("tenant filter %v, want %s", f.TenantID, tenant)
		}
		if f.ActorID == nil || f.ActorID.String() != actor || len(f.Actions) != 2 || len(f.ResourceTypes) != 1 ||
			f.ResourceID == nil || *f.ResourceID != "res-1" || len(f.Results) != 1 || len(f.Severities) != 1 ||
			f.RequestID == nil || *f.RequestID != "req-9" || f.Since == nil || f.Until == nil ||
			f.SearchTerm == nil || *f.SearchTerm != "hello" || !f.ExcludeSystem {
			t.Fatalf("filters not applied: %+v", f)
		}
	}
	// An empty export still has its header row.
	if !strings.HasPrefix(rec.Body.String(), "time,action,") {
		t.Fatalf("body %q", rec.Body.String())
	}
}

func TestAuditExport_RefusesWhatTheListRefuses(t *testing.T) {
	repo := &exportAuditRepo{rows: []*auditdom.AuditLog{exportTestRow("x", "")}}
	h := newExportHandler(repo)
	// A member without full data access: the same 403 as the list.
	if rec := exportRequest(h, "/api/v1/audit-logs/export", false, shared.NewID().String()); rec.Code != http.StatusForbidden {
		t.Fatalf("member: %d", rec.Code)
	}
	if rec := exportRequest(h, "/api/v1/audit-logs/export?format=xml", true, shared.NewID().String()); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format: %d", rec.Code)
	}
	if rec := exportRequest(h, "/api/v1/audit-logs/export", true, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no tenant: %d", rec.Code)
	}
	if repo.batches != 0 {
		t.Fatal("a refused export must not read rows")
	}
}

func TestAuditExport_IsAudited(t *testing.T) {
	tenant := shared.NewID().String()
	repo := &exportAuditRepo{rows: []*auditdom.AuditLog{exportTestRow("a", ""), exportTestRow("b", "")}}
	rec := exportRequest(newExportHandler(repo), "/api/v1/audit-logs/export?format=jsonl&severity=high&search=x", true, tenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var ev *auditdom.AuditLog
	for _, l := range repo.logs {
		if l.Action() == auditdom.ActionAuditLogExported {
			ev = l
		}
	}
	if ev == nil {
		t.Fatal("no audit_log.exported event was written")
	}
	if ev.Severity() != auditdom.SeverityMedium || ev.TenantID() == nil || ev.TenantID().String() != tenant {
		t.Fatalf("severity %s tenant %v", ev.Severity(), ev.TenantID())
	}
	md := ev.Metadata()
	if md["format"] != "jsonl" || md["rows"] != 2 || md["truncated"] != false {
		t.Fatalf("metadata %v", md)
	}
	filters, _ := md["filters"].([]string)
	if len(filters) != 2 || filters[0] != "severity" || filters[1] != "search" {
		t.Fatalf("filters %v (names only, never values)", md["filters"])
	}
	// The export does not list its own event.
	if strings.Contains(rec.Body.String(), "audit_log.exported") {
		t.Fatal("the export listed its own event")
	}
}
