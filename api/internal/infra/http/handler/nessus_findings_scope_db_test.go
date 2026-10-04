package handler

// POST /api/v1/assets/import/nessus-findings against real Postgres. The
// upload ran as a trusted server-side sensor: a default member (assets:write
// + findings:write) could add findings to assets outside their data scope,
// auto-resolve every open finding of a tool on any host by listing it with
// no items, and choose that tool with ?tool=. It now runs with the
// uploader's rights. Research doc 15, L-05.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// nfsHost is one ReportHost; plugins are the ReportItem plugin ids (none:
// the host was scanned and nothing was found).
type nfsHost struct {
	fqdn    string
	plugins []int
}

func nfsReport(hosts ...nfsHost) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" ?><NessusClientData_v2><Report name="nfs">`)
	for i, h := range hosts {
		fmt.Fprintf(&b, `<ReportHost name="%s"><HostProperties><tag name="host-ip">10.77.0.%d</tag><tag name="host-fqdn">%s</tag></HostProperties>`,
			h.fqdn, i+10, h.fqdn)
		for _, p := range h.plugins {
			fmt.Fprintf(&b, `<ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="%d" pluginName="nfs plugin %d" pluginFamily="General">`+
				`<synopsis>nfs synopsis %d</synopsis><description>nfs description %d</description><risk_factor>High</risk_factor></ReportItem>`, p, p, p, p)
		}
		b.WriteString(`</ReportHost>`)
	}
	b.WriteString(`</Report></NessusClientData_v2>`)
	return b.String()
}

func TestNessusFindingsUpload_UploaderScope_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	tenant := shared.NewID().String()
	admin, scoped := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'nfs', $2)`, tenant, "nfs-"+tenant)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tenant)
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenant)
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'nfs')`, u, u+"@nfs.test")
	}
	suffix := strings.ReplaceAll(tenant, "-", "")[:12]
	hostIn, hostOut, hostNew := "in-"+suffix+".nfs.test", "out-"+suffix+".nfs.test", "new-"+suffix+".nfs.test"

	db := &postgres.DB{DB: raw}
	log := logger.NewNop()
	sensorRepo := postgres.NewSensorRepository(db)
	ingestSvc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil,
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	h := NewAssetImportHandler(app.NewAssetImportService(postgres.NewAssetRepository(db), log), ingestSvc, log)
	h.SetDataScope(enforcer)

	type result struct {
		AssetsCreated           int `json:"assets_created"`
		AssetsSkippedOutOfScope int `json:"assets_skipped_out_of_scope"`
		FindingsCreated         int `json:"findings_created"`
		FindingsAutoResolved    int `json:"findings_auto_resolved"`
	}
	upload := func(user string, isAdmin bool, query, body string) result {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/import/nessus-findings?"+query, strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		c = context.WithValue(c, middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, isAdmin)
		w := httptest.NewRecorder()
		h.IngestNessusFindings(w, req.WithContext(c))
		if w.Code != http.StatusOK {
			t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
		}
		var out struct {
			Result result `json:"result"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v", w.Body.String(), err)
		}
		return out.Result
	}
	assetID := func(name string) string {
		t.Helper()
		var id string
		if err := raw.QueryRowContext(ctx, `SELECT id::text FROM assets WHERE tenant_id = $1 AND name = $2`, tenant, name).Scan(&id); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return id
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := raw.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("count %q: %v", q, err)
		}
		return n
	}
	openFindings := func(asset, tool string) int {
		return count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND tool_name = $3
			AND status NOT IN ('resolved', 'auto_fixed')`, tenant, asset, tool)
	}

	// The administrator's first batch creates both hosts with one finding each.
	if r := upload(admin, true, "", nfsReport(nfsHost{hostIn, []int{1001}}, nfsHost{hostOut, []int{1002}})); r.AssetsCreated != 2 || r.FindingsCreated != 2 {
		t.Fatalf("admin batch = %+v, want 2 assets and 2 findings", r)
	}
	in, out := assetID(hostIn), assetID(hostOut)
	// scoped may change hostIn only (organizations are fail-closed by default).
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenant, in)
	// Another scanner's open finding on hostIn.
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'dast', 'nuclei', 'nfs nuclei finding', 'high', $1::text, 'confirmed')`,
		shared.NewID().String(), tenant, in)
	// Network findings carry no branch, and the auto-resolve query only
	// closes findings on a default branch, so give both hosts one and attach
	// their current findings to it: the upload paths below could then close
	// them, which is what the gates must prevent.
	for _, a := range []string{in, out} {
		exec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, a)
		exec(`INSERT INTO repository_branches (repository_id, name, is_default) VALUES ($1, 'network', true)`, a)
		exec(`UPDATE findings SET branch_id = (SELECT id FROM repository_branches WHERE repository_id = $1)
			WHERE tenant_id = $2 AND asset_id = $1`, a, tenant)
	}
	var outSeen string
	_ = raw.QueryRowContext(ctx, `SELECT updated_at::text FROM assets WHERE id = $1`, out).Scan(&outSeen)

	// The scoped member uploads all three hosts with new items.
	r := upload(scoped, false, "", nfsReport(nfsHost{hostIn, []int{2001}}, nfsHost{hostOut, []int{2002}}, nfsHost{hostNew, []int{2003}}))
	if r.FindingsCreated != 1 || r.AssetsCreated != 0 || r.AssetsSkippedOutOfScope != 2 {
		t.Errorf("scoped upload = %+v, want 1 finding (in-scope host), 0 assets created, 2 hosts skipped", r)
	}
	if n := count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2`, tenant, out); n != 1 {
		t.Errorf("out-of-scope host has %d findings, want 1 (the scoped upload added one)", n)
	}
	if n := count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tenant, hostNew); n != 0 {
		t.Error("the scoped upload created a host the member could not see")
	}
	var outSeenAfter string
	_ = raw.QueryRowContext(ctx, `SELECT updated_at::text FROM assets WHERE id = $1`, out).Scan(&outSeenAfter)
	if outSeenAfter != outSeen {
		t.Errorf("the out-of-scope host was touched (updated_at %s -> %s)", outSeen, outSeenAfter)
	}

	// The scoped member lists every host with no items: nothing auto-resolves,
	// in scope or not, and a hidden host answers like a missing one.
	r = upload(scoped, false, "", nfsReport(nfsHost{hostIn, nil}, nfsHost{hostOut, nil}))
	if r.FindingsAutoResolved != 0 || openFindings(out, "tenable") != 1 || openFindings(in, "tenable") != 2 {
		t.Errorf("scoped empty upload resolved findings: %+v (open in=%d out=%d)", r, openFindings(in, "tenable"), openFindings(out, "tenable"))
	}
	hidden := upload(scoped, false, "", nfsReport(nfsHost{hostOut, nil}))
	missing := upload(scoped, false, "", nfsReport(nfsHost{"missing-" + suffix + ".nfs.test", nil}))
	if hidden != missing {
		t.Errorf("an out-of-scope host answered %+v, a missing host %+v: must be identical", hidden, missing)
	}

	// An administrator with a typed ?tool= does not close that tool's findings.
	if r := upload(admin, true, "tool=nuclei", nfsReport(nfsHost{hostIn, nil})); r.FindingsAutoResolved != 0 || openFindings(in, "nuclei") != 1 {
		t.Errorf("admin ?tool=nuclei upload resolved nuclei findings: %+v", r)
	}
	// An administrator's Tenable batch still auto-resolves on its hosts (the
	// finding on the seeded branch; the scoped upload's has none).
	if r := upload(admin, true, "", nfsReport(nfsHost{hostIn, nil})); r.FindingsAutoResolved != 1 || openFindings(in, "tenable") != 1 {
		t.Errorf("admin tenable batch = %+v (open %d), want the branch finding on the host resolved", r, openFindings(in, "tenable"))
	}
	if openFindings(in, "nuclei") != 1 || openFindings(out, "tenable") != 1 {
		t.Error("the admin batch resolved findings of another tool or another host")
	}
}
