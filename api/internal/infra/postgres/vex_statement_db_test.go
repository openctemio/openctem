package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	vexapp "github.com/openctemio/openctem/api/internal/app/vex"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// vexScope is a member's data scope: restricted to the listed assets, or
// unrestricted.
type vexScope struct {
	tenant, user shared.ID
	restricted   bool
	assets       map[shared.ID]bool
}

func (s *vexScope) Resolve(_ context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if !s.restricted {
		return nil, nil
	}
	return &shared.DataScope{TenantID: tenantID, UserID: s.user}, nil
}

func (s *vexScope) AssertAsset(_ context.Context, tenantID, assetID shared.ID) error {
	if tenantID != s.tenant || (s.restricted && !s.assets[assetID]) {
		return shared.ErrNotFound
	}
	return nil
}

type vexAudit struct{ actions []auditdom.Action }

func (a *vexAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.actions = append(a.actions, e.Action)
	return nil
}

type vexFixture struct {
	t          *testing.T
	db         *sql.DB
	tenant     shared.ID
	other      shared.ID
	a1, a2, b1 shared.ID
	product    string
	v20, v21   string
	user       shared.ID
}

func newVEXFixture(t *testing.T) *vexFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping VEX statement DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	f := &vexFixture{t: t, db: db, tenant: shared.NewID(), other: shared.NewID(), a1: shared.NewID(), a2: shared.NewID(), b1: shared.NewID()}
	for _, tid := range []shared.ID{f.tenant, f.other} {
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "vex-"+tid.String())
		tid := tid
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	for asset, tenant := range map[shared.ID]shared.ID{f.a1: f.tenant, f.a2: f.tenant, f.b1: f.other} {
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
			asset.String(), tenant.String(), "vex-"+asset.String())
	}
	// A global package (the feed's) used by both tenants; versions unique
	// per run.
	suffix := shared.NewID().String()[:8]
	f.product, f.v20 = testdb.SeedPackageVersion(t, db, "", "pkg:npm/vexlodash"+suffix+"@4.17.20")
	_, f.v21 = testdb.SeedPackageVersion(t, db, "", "pkg:npm/vexlodash"+suffix+"@4.17.21")
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM software_products WHERE id = $1`, f.product) })
	testdb.SeedPackageLink(t, db, f.tenant.String(), f.a1.String(), f.product, f.v20, "package-lock.json", "direct")
	testdb.SeedPackageLink(t, db, f.tenant.String(), f.a2.String(), f.product, f.v20, "package-lock.json", "direct")
	f.user = seedGroupsUser(ctx, t, db, "vex-"+suffix+".test")
	addTenantMember(ctx, t, db, f.tenant, f.user)
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		f.user.String(), f.tenant.String(), f.a1.String())
	return f
}

func (f *vexFixture) finding(tenant, asset shared.ID, version, cve, source, status string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	mustExec(f.t, f.db, `INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, severity, fingerprint, status, cve_id)
		VALUES ($1, $2, $3, $4, $5, 'trivy', 'm', 'high', $6, $7, $8)`,
		id.String(), tenant.String(), asset.String(), version, source, "fp-"+id.String(), status, cve)
	return id
}

func (f *vexFixture) state(id shared.ID) (status, method string, stmt *string) {
	f.t.Helper()
	var m, s sql.NullString
	if err := f.db.QueryRow(`SELECT status, resolution_method, vex_statement_id::text FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &m, &s); err != nil {
		f.t.Fatal(err)
	}
	if s.Valid {
		stmt = &s.String
	}
	return status, m.String, stmt
}

func (f *vexFixture) wantStatus(id shared.ID, want, method string) {
	f.t.Helper()
	status, m, _ := f.state(id)
	if status != want || m != method {
		f.t.Errorf("finding %s: status %s (%s), want %s (%s)", id, status, m, want, method)
	}
}

func TestVEXStatements_DB(t *testing.T) {
	f := newVEXFixture(t)
	ctx := context.Background()
	repo := NewVEXStatementRepository(&DB{DB: f.db})
	audit := &vexAudit{}
	full := &vexScope{tenant: f.tenant}
	svc := vexapp.NewService(repo, full, audit, nil)
	now := time.Now().UTC()
	svc.SetClock(func() time.Time { return now })
	actx := auditapp.AuditContext{TenantID: f.tenant.String(), ActorID: f.user.String()}

	f1 := f.finding(f.tenant, f.a1, f.v20, "CVE-2021-23337", "sca", "new")
	f2 := f.finding(f.tenant, f.a2, f.v20, "CVE-2021-23337", "sca", "confirmed")
	f3 := f.finding(f.tenant, f.a1, f.v21, "CVE-2021-23337", "sca", "in_progress")
	pen := f.finding(f.tenant, f.a1, f.v20, "CVE-2021-23337", "pentest", "new")
	other := f.finding(f.tenant, f.a1, f.v20, "CVE-2020-8203", "sca", "new")
	foreign := f.finding(f.other, f.b1, f.v20, "CVE-2021-23337", "sca", "new")

	// 1. A statement for every asset at 4.17.20 closes the open, non-human
	// findings it covers, and nothing in another tenant.
	expiry := now.Add(48 * time.Hour)
	st, res, err := svc.Create(ctx, f.tenant, vexapp.Input{
		VulnID: "cve-2021-23337", ProductID: f.product, Versions: []string{"4.17.20"}, Status: "not_affected",
		Justification: "vulnerable_code_not_in_execute_path", ExpiresAt: &expiry,
	}, actx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Closed != 2 {
		t.Errorf("closed %d, want 2 (%+v)", res.Closed, res)
	}
	f.wantStatus(f1, "false_positive", "vex_not_affected")
	f.wantStatus(f2, "false_positive", "vex_not_affected")
	f.wantStatus(f3, "in_progress", "")
	f.wantStatus(other, "new", "")
	f.wantStatus(foreign, "new", "")
	if status, _, sid := f.state(pen); status != "new" || sid == nil || *sid != st.ID.String() {
		t.Errorf("a pentest finding is annotated, never closed: %s %v", status, sid)
	}
	var acts int
	if err := f.db.QueryRow(`SELECT count(*) FROM finding_activities WHERE finding_id = $1 AND changes->>'reason' = 'vex_statement'`,
		f1.String()).Scan(&acts); err != nil || acts != 1 {
		t.Errorf("activity entry for the closure: %d %v", acts, err)
	}
	if _, _, err := svc.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-23337", ProductID: f.product,
		Versions: []string{"4.17.20"}, Status: "affected"}, actx); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("same subject twice: %v", err)
	}

	// 2. A statement for one asset wins over the one for every asset.
	onA1, _, err := svc.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-23337", PURL: "pkg:npm/" + f.purlName(),
		AssetID: f.a1.String(), Status: "affected", ActionStatement: "upgrade"}, actx)
	if err != nil {
		t.Fatalf("asset-bound create: %v", err)
	}
	f.wantStatus(f1, "new", "")
	f.wantStatus(f2, "false_positive", "vex_not_affected")
	f.wantStatus(f3, "in_progress", "")
	if _, err := svc.Delete(ctx, f.tenant, onA1.ID.String(), actx); err != nil {
		t.Fatalf("delete: %v", err)
	}
	f.wantStatus(f1, "false_positive", "vex_not_affected")

	// 3. Widening to a range covers 4.17.21 too; status fixed resolves.
	rng := ">=4.17.0,<4.17.22"
	fixed := "fixed"
	if _, res, err = svc.Update(ctx, f.tenant, st.ID.String(), vexapp.Patch{VersionRange: &rng}, actx); err != nil {
		t.Fatalf("update range: %v", err)
	}
	f.wantStatus(f3, "false_positive", "vex_not_affected")
	if _, _, err = svc.Update(ctx, f.tenant, st.ID.String(), vexapp.Patch{Status: &fixed}, actx); err != nil {
		t.Fatalf("update status: %v", err)
	}
	for _, id := range []shared.ID{f1, f2, f3} {
		f.wantStatus(id, "resolved", "vex_fixed")
	}

	// 4. A finding reported later is covered (sticky), and a scan that
	// reports a finding the statement marks fixed does not reopen it.
	f4 := f.finding(f.tenant, f.a2, f.v21, "CVE-2021-23337", "sca", "new")
	if n, err := svc.ApplyToFingerprints(ctx, f.tenant, []string{"fp-" + f4.String()}); err != nil || n != 1 {
		t.Fatalf("sticky: %d %v", n, err)
	}
	f.wantStatus(f4, "resolved", "vex_fixed")
	reopened, err := NewFindingRepository(&DB{DB: f.db}).AutoReopenByFingerprintsBatch(ctx, f.tenant, []string{"fp-" + f4.String()})
	if err != nil || len(reopened) != 0 {
		t.Fatalf("regression reopen must skip a vex_fixed finding: %v %v", reopened, err)
	}

	// 5. Expiry withdraws the statement: findings reopen, audited.
	now = expiry.Add(time.Minute)
	if n, err := svc.ExpireDue(ctx, 50); err != nil || n < 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	for _, id := range []shared.ID{f1, f2, f3, f4} {
		f.wantStatus(id, "confirmed", "")
	}
	if _, _, sid := f.state(f1); sid != nil {
		t.Error("an expired statement is no longer carried")
	}
	got, err := repo.Get(ctx, f.tenant, st.ID)
	if err != nil || got.ExpiredAt == nil {
		t.Fatalf("expired_at recorded: %v", err)
	}
	if !hasAction(audit.actions, auditdom.ActionVEXStatementExpired) || !hasAction(audit.actions, auditdom.ActionVEXStatementCreated) ||
		!hasAction(audit.actions, auditdom.ActionVEXStatementDeleted) || !hasAction(audit.actions, auditdom.ActionVEXStatementApplied) {
		t.Errorf("audit actions: %v", audit.actions)
	}
}

func (f *vexFixture) purlName() string {
	var name string
	if err := f.db.QueryRow(`SELECT purl_name FROM software_products WHERE id = $1`, f.product).Scan(&name); err != nil {
		f.t.Fatal(err)
	}
	return name
}

func hasAction(actions []auditdom.Action, a auditdom.Action) bool {
	for _, x := range actions {
		if x == a {
			return true
		}
	}
	return false
}

// Cross-tenant and data-scope negatives.
func TestVEXStatements_Isolation_DB(t *testing.T) {
	f := newVEXFixture(t)
	ctx := context.Background()
	repo := NewVEXStatementRepository(&DB{DB: f.db})
	svc := vexapp.NewService(repo, &vexScope{tenant: f.tenant}, nil, nil)
	actx := auditapp.AuditContext{TenantID: f.tenant.String()}

	st, _, err := svc.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-1", ProductID: f.product, AssetID: f.a2.String(),
		Status: "under_investigation"}, actx)
	if err != nil {
		t.Fatal(err)
	}
	wide, _, err := svc.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-2", ProductID: f.product, Status: "affected"}, actx)
	if err != nil {
		t.Fatal(err)
	}

	// Another tenant: the statement does not exist.
	otherSvc := vexapp.NewService(repo, &vexScope{tenant: f.other}, nil, nil)
	if _, err := otherSvc.Get(ctx, f.other, st.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant get: %v", err)
	}
	if _, err := otherSvc.Delete(ctx, f.other, st.ID.String(), actx); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant delete: %v", err)
	}
	if page, _ := otherSvc.List(ctx, f.other, vexapp.ListInput{}, pagination.New(1, 50)); page.Total != 0 {
		t.Errorf("cross-tenant list: %d", page.Total)
	}
	// A package private to the tenant cannot be named by another tenant,
	// and the database refuses a statement pointing at it.
	private, _ := testdb.SeedPackageVersion(t, f.db, f.tenant.String(), "pkg:npm/@acme/vex-internal-"+f.tenant.String()[:8]+"@1.0.0")
	if _, _, err := otherSvc.Create(ctx, f.other, vexapp.Input{VulnID: "CVE-2021-3", ProductID: private, Status: "affected"},
		actx); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("another tenant's private package: %v", err)
	}
	if _, err := f.db.Exec(`INSERT INTO vex_statements (tenant_id, vuln_id, product_id, status, origin) VALUES ($1, 'CVE-2021-3', $2, 'affected', 'manual')`,
		f.other.String(), private); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Errorf("trigger must refuse another tenant's product: %v", err)
	}
	if _, err := f.db.Exec(`INSERT INTO vex_statements (tenant_id, vuln_id, product_id, asset_id, status, origin) VALUES ($1, 'CVE-2021-3', $2, $3, 'affected', 'manual')`,
		f.other.String(), f.product, f.a1.String()); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Errorf("trigger must refuse another tenant's asset: %v", err)
	}

	// A member restricted to a1.
	member := vexapp.NewService(repo, &vexScope{tenant: f.tenant, user: f.user, restricted: true,
		assets: map[shared.ID]bool{f.a1: true}}, nil, nil)
	if _, _, err := member.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-4", ProductID: f.product, Status: "affected"},
		actx); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("a statement for every asset needs full data access: %v", err)
	}
	if _, _, err := member.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-4", ProductID: f.product, AssetID: f.a2.String(),
		Status: "affected"}, actx); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("an out-of-scope asset answers not found: %v", err)
	}
	if _, _, err := member.Create(ctx, f.tenant, vexapp.Input{VulnID: "CVE-2021-4", ProductID: f.product, AssetID: f.a1.String(),
		Status: "affected"}, actx); err != nil {
		t.Errorf("in-scope asset: %v", err)
	}
	if _, err := member.Get(ctx, f.tenant, st.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("statement on an out-of-scope asset is hidden: %v", err)
	}
	if _, err := member.Get(ctx, f.tenant, wide.ID.String()); err != nil {
		t.Errorf("tenant-wide statement on a package an in-scope asset uses: %v", err)
	}
	if _, err := member.Delete(ctx, f.tenant, wide.ID.String(), actx); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("deleting a statement for every asset needs full data access: %v", err)
	}
	page, err := member.List(ctx, f.tenant, vexapp.ListInput{}, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range page.Data {
		if s.ID == st.ID {
			t.Error("list shows a statement on an out-of-scope asset")
		}
	}
	if page.Total != 2 {
		t.Errorf("member sees the tenant-wide and its own asset statement: %d", page.Total)
	}
}

func TestVEXStatements_Import_DB(t *testing.T) {
	f := newVEXFixture(t)
	ctx := context.Background()
	repo := NewVEXStatementRepository(&DB{DB: f.db})
	audit := &vexAudit{}
	svc := vexapp.NewService(repo, &vexScope{tenant: f.tenant}, audit, nil)
	actx := auditapp.AuditContext{TenantID: f.tenant.String()}
	fnd := f.finding(f.tenant, f.a1, f.v20, "CVE-2021-23337", "sca", "new")

	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/2","author":"Security",
"timestamp":"2026-10-01T00:00:00Z","version":1,"statements":[
 {"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/` + f.purlName() + `@4.17.20"}],"status":"not_affected",
  "justification":"vulnerable_code_not_present"},
 {"vulnerability":{"name":"CVE-2021-1000"},"products":[{"@id":"pkg:npm/not-in-inventory-x@1.0.0"}],"status":"not_affected",
  "justification":"vulnerable_code_not_present"}]}`

	prev, err := svc.Import(ctx, f.tenant, "", strings.NewReader(doc), true, actx)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.Created != 1 || prev.SkippedTotal != 1 || len(prev.Items) != 1 || prev.Items[0].Action != "create" {
		t.Fatalf("preview: %+v", prev)
	}
	var n int
	_ = f.db.QueryRow(`SELECT count(*) FROM vex_statements WHERE tenant_id = $1`, f.tenant.String()).Scan(&n)
	if n != 0 {
		t.Fatal("a preview writes nothing")
	}
	f.wantStatus(fnd, "new", "")

	res, err := svc.Import(ctx, f.tenant, "", strings.NewReader(doc), false, actx)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Created != 1 || res.Applied.Closed != 1 {
		t.Fatalf("import: %+v", res)
	}
	f.wantStatus(fnd, "false_positive", "vex_not_affected")
	var origin, ref string
	_ = f.db.QueryRow(`SELECT origin, document_ref FROM vex_statements WHERE tenant_id = $1`, f.tenant.String()).Scan(&origin, &ref)
	if origin != "document" || !strings.HasPrefix(ref, "openvex") {
		t.Errorf("origin %s ref %s", origin, ref)
	}
	again, err := svc.Import(ctx, f.tenant, "", strings.NewReader(doc), false, actx)
	if err != nil || again.Unchanged != 1 || again.Created != 0 {
		t.Fatalf("re-import is idempotent: %+v %v", again, err)
	}
	if !hasAction(audit.actions, auditdom.ActionVEXStatementImported) {
		t.Error("import audited")
	}

	// A member restricted to part of the tenant imports only for an asset.
	member := vexapp.NewService(repo, &vexScope{tenant: f.tenant, user: f.user, restricted: true,
		assets: map[shared.ID]bool{f.a1: true}}, nil, nil)
	if _, err := member.Import(ctx, f.tenant, "", strings.NewReader(doc), true, actx); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("tenant-wide import by a restricted member: %v", err)
	}
	if _, err := member.Import(ctx, f.tenant, f.a2.String(), strings.NewReader(doc), true, actx); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("import for an out-of-scope asset: %v", err)
	}
}
