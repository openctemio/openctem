package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type receiptReadHarness struct {
	t                          *testing.T
	db                         *sql.DB
	srv                        *httptest.Server
	tenantA, tenantB           string
	admin, scoped, orgViewer   string
	fIn, fOut                  string
	runRec, uploadRec, foreign string
}

func (h *receiptReadHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newReceiptReadHarness(t *testing.T) *receiptReadHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	h := &receiptReadHarness{t: t, db: sqldb}
	id := func() string { return shared.NewID().String() }
	h.tenantA, h.tenantB = id(), id()
	h.admin, h.scoped, h.orgViewer = id(), id(), id()
	for _, tn := range []string{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn, "rr-"+tn)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []string{h.tenantA, h.tenantB} {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{h.admin, h.scoped, h.orgViewer} {
			_, _ = sqldb.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{h.admin, h.scoped, h.orgViewer} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rr')`, u, u+"@rr.test")
	}
	assetIn, assetOut, assetB := id(), id(), id()
	for aid, tn := range map[string]string{assetIn: h.tenantA, assetOut: h.tenantA, assetB: h.tenantB} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, aid, tn, "rr-"+aid)
	}
	finding := func(tn, asset, sev string) string {
		fid := id()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'dast', 'nuclei', 'm', $5, $4, $6, 'new')`, fid, tn, asset, sev, "t-"+fid, "fp-"+fid)
		return fid
	}
	h.fIn, h.fOut = finding(h.tenantA, assetIn, "high"), finding(h.tenantA, assetOut, "critical")
	fB := finding(h.tenantB, assetB, "low")
	// The scoped member and the organization viewer see assetIn only.
	for _, u := range []string{h.scoped, h.orgViewer} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			u, h.tenantA, assetIn)
	}

	db := &postgres.DB{DB: sqldb}
	repo := postgres.NewIngestReceiptRepository(db)
	ctx := context.Background()
	record := func(tn string, src ingestreceipt.Source, created ...string) string {
		ids := make([]shared.ID, 0, len(created))
		for _, c := range created {
			ids = append(ids, shared.MustIDFromString(c))
		}
		rid, err := repo.Record(ctx, &ingestreceipt.Delta{TenantID: shared.MustIDFromString(tn), Source: src, Tool: "nuclei", Reports: 1, Created: ids})
		if err != nil {
			t.Fatal(err)
		}
		return rid.String()
	}
	h.runRec = record(h.tenantA, ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "sync-" + id()}, h.fIn, h.fOut)
	up := shared.NewID()
	actor := shared.MustIDFromString(h.scoped)
	if err := repo.CreateUpload(ctx, &ingestreceipt.Upload{ID: up, TenantID: shared.MustIDFromString(h.tenantA), ActorUserID: &actor}); err != nil {
		t.Fatal(err)
	}
	h.uploadRec = record(h.tenantA, ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: up.String()}, h.fIn)
	h.foreign = record(h.tenantB, ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "sync-b"}, fB)

	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
	}, log)
	enforcer.SetAggregateCheck(func(ctx context.Context) bool {
		return middleware.HasPermission(ctx, permission.DashboardsOrgView.String())
	})
	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Header.Get("X-Test-User")
			perms := []string{permission.FindingsRead.String()}
			if user == h.orgViewer {
				perms = append(perms, permission.DashboardsOrgView.String())
			}
			c := context.WithValue(r.Context(), middleware.UserIDKey, user)
			c = context.WithValue(c, middleware.TenantIDKey, h.tenantA)
			c = context.WithValue(c, middleware.IsAdminKey, user == h.admin)
			c = context.WithValue(c, middleware.PermissionsKey, perms)
			c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
			next.ServeHTTP(w, r.WithContext(c))
		})
	})
	pass := Middleware(func(next http.Handler) http.Handler { return next })
	registerFindingImportRoutes(router, nil, handler.NewIngestReceiptHandler(repo, enforcer, log), auth, pass)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *receiptReadHarness) get(user, path string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	req.Header.Set("X-Test-User", user)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func receiptIDs(t *testing.T, body map[string]any, key string) []string {
	t.Helper()
	var out []string
	data, _ := body["data"].([]any)
	for _, d := range data {
		m, _ := d.(map[string]any)
		out = append(out, m[key].(string))
	}
	return out
}

func sameIDSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	m := map[string]bool{}
	for _, g := range got {
		m[g] = true
	}
	for _, w := range want {
		if !m[w] {
			return false
		}
	}
	return true
}

// Receipt counts are organization-wide: an administrator and an
// organization viewer list every receipt of the tenant; a restricted member
// lists only their own upload and gets 404 on any other receipt; nobody sees
// another tenant's receipt. Per-finding rows and severity counts are limited
// to the caller's data scope for everyone.
func TestIngestReceipts_Visibility_DB(t *testing.T) {
	h := newReceiptReadHarness(t)

	for _, u := range []string{h.admin, h.orgViewer} {
		code, body := h.get(u, "/api/v1/findings/imports")
		if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "id"), h.runRec, h.uploadRec) {
			t.Fatalf("%s list: %d %v", u, code, body)
		}
	}
	code, body := h.get(h.scoped, "/api/v1/findings/imports")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "id"), h.uploadRec) {
		t.Fatalf("scoped list: %d %v", code, body)
	}
	for _, p := range []string{"", "/actions"} {
		if code, _ := h.get(h.scoped, "/api/v1/findings/imports/"+h.runRec+p); code != http.StatusNotFound {
			t.Fatalf("scoped read another member's receipt%s: %d", p, code)
		}
		if code, _ := h.get(h.admin, "/api/v1/findings/imports/"+h.foreign+p); code != http.StatusNotFound {
			t.Fatalf("admin read another tenant's receipt%s: %d", p, code)
		}
	}

	// The organization viewer sees the stored, organization-wide counts but
	// only the actions on findings in their scope.
	code, body = h.get(h.orgViewer, "/api/v1/findings/imports/"+h.runRec)
	if code != http.StatusOK {
		t.Fatalf("org viewer detail: %d", code)
	}
	counts := body["counts"].(map[string]any)
	by := body["by_severity"].(map[string]any)["created"].(map[string]any)
	if counts["created"].(float64) != 2 || by["high"].(float64) != 1 || by["critical"] != nil {
		t.Fatalf("org viewer counts %v by severity %v", counts, by)
	}
	code, body = h.get(h.orgViewer, "/api/v1/findings/imports/"+h.runRec+"/actions")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "finding_id"), h.fIn) {
		t.Fatalf("org viewer actions: %d %v", code, body)
	}
	code, body = h.get(h.admin, "/api/v1/findings/imports/"+h.runRec+"/actions?action=created")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "finding_id"), h.fIn, h.fOut) {
		t.Fatalf("admin actions: %d %v", code, body)
	}
	code, body = h.get(h.scoped, "/api/v1/findings/imports/"+h.uploadRec+"/actions")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "finding_id"), h.fIn) {
		t.Fatalf("scoped own upload actions: %d %v", code, body)
	}

	// A finding's receipts: in scope only.
	if code, _ := h.get(h.scoped, "/api/v1/findings/"+h.fOut+"/imports"); code != http.StatusNotFound {
		t.Fatalf("scoped read an out-of-scope finding's receipts: %d", code)
	}
	code, body = h.get(h.scoped, "/api/v1/findings/"+h.fIn+"/imports")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "receipt_id"), h.runRec, h.uploadRec) {
		t.Fatalf("finding receipts: %d %v", code, body)
	}
	if _, has := body["data"].([]any)[0].(map[string]any)["counts"]; has {
		t.Fatal("a finding's receipt entry carries counts")
	}
}

// The list contract: an unknown parameter is refused instead of ignored (it
// must not widen the result), a bad enum value too, and per_page is capped.
func TestIngestReceipts_ListContract_DB(t *testing.T) {
	h := newReceiptReadHarness(t)
	for _, q := range []string{"?sourcekind=upload", "?source_kind=everything", "?per_page=abc",
		"?action=created", "?source_kind=upload&tenant_id=" + h.tenantB} {
		code, body := h.get(h.admin, "/api/v1/findings/imports"+q)
		if code != http.StatusBadRequest || body["code"] != "INVALID_FILTER" {
			t.Fatalf("%s: %d %v", q, code, body)
		}
	}
	if code, body := h.get(h.admin, "/api/v1/findings/imports/"+h.runRec+"/actions?state=x"); code != http.StatusBadRequest {
		t.Fatalf("actions unknown param: %d %v", code, body)
	}
	code, body := h.get(h.admin, "/api/v1/findings/imports?per_page=100000")
	if code != http.StatusOK || body["per_page"].(float64) != 100 {
		t.Fatalf("per_page not capped: %d %v", code, body["per_page"])
	}
	code, body = h.get(h.admin, "/api/v1/findings/imports?source_kind=upload")
	if code != http.StatusOK || !sameIDSet(receiptIDs(t, body, "id"), h.uploadRec) || !strings.Contains(h.uploadRec, "-") {
		t.Fatalf("source_kind filter: %d %v", code, body)
	}
}
