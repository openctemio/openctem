package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/compliance"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// deleteAuditFixture is two tenants, a user and an audit service that writes
// to the real audit_logs table.
type deleteAuditFixture struct {
	db       *sql.DB
	pg       *postgres.DB
	tenantA  string
	tenantB  string
	userID   string
	auditSvc *auditapp.AuditService
}

func newDeleteAuditFixture(t *testing.T) *deleteAuditFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	f := &deleteAuditFixture{
		db: db, pg: &postgres.DB{DB: db},
		tenantA: shared.NewID().String(), tenantB: shared.NewID().String(), userID: shared.NewID().String(),
	}
	for _, id := range []string{f.tenantA, f.tenantB} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,'Delete Audit Org',$2)`, id, "da-"+id); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, f.userID, "admin-"+f.userID+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		for _, id := range []string{f.tenantA, f.tenantB} {
			for _, q := range []string{
				`DELETE FROM audit_log_chain WHERE tenant_id=$1`, `DELETE FROM audit_logs WHERE tenant_id=$1`,
				`DELETE FROM asset_relationships WHERE tenant_id=$1`, `DELETE FROM assets WHERE tenant_id=$1`,
				`DELETE FROM attacker_profiles WHERE tenant_id=$1`, `DELETE FROM business_services WHERE tenant_id=$1`,
				`DELETE FROM business_units WHERE tenant_id=$1`, `DELETE FROM asset_groups WHERE tenant_id=$1`,
				`DELETE FROM pentest_finding_templates WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`,
			} {
				_, _ = db.ExecContext(ctx, q, id)
			}
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, f.userID)
		_ = db.Close()
	})
	f.auditSvc = auditapp.NewAuditService(postgres.NewAuditRepository(f.pg), logger.NewNop())
	return f
}

func (f *deleteAuditFixture) req(method, target, tenant string, body []byte, params ...string) *http.Request {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	c := context.WithValue(r.Context(), middleware.TenantIDKey, tenant)
	c = context.WithValue(c, middleware.UserIDKey, f.userID)
	r = r.WithContext(c)
	for i := 0; i+1 < len(params); i += 2 {
		r = withURLParam(r, params[i], params[i+1])
	}
	return r
}

type auditRow struct{ resourceID, name, resourceType, severity, actor string }

// entries returns the audit rows of one action recorded for a tenant.
func (f *deleteAuditFixture) entries(t *testing.T, tenant string, action auditdom.Action) []auditRow {
	t.Helper()
	rows, err := f.db.Query(`SELECT resource_id, COALESCE(resource_name,''), resource_type, severity, COALESCE(actor_id::text,'')
		FROM audit_logs WHERE tenant_id=$1 AND action=$2 ORDER BY resource_id`, tenant, string(action))
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.resourceID, &r.name, &r.resourceType, &r.severity, &r.actor); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	return out
}

// total counts every audit row of the action in both tenants.
func (f *deleteAuditFixture) total(t *testing.T, action auditdom.Action) int {
	t.Helper()
	return len(f.entries(t, f.tenantA, action)) + len(f.entries(t, f.tenantB, action))
}

func (f *deleteAuditFixture) wantOne(t *testing.T, action auditdom.Action, rtype auditdom.ResourceType, id, name string) {
	t.Helper()
	got := f.entries(t, f.tenantA, action)
	if len(got) != 1 {
		t.Fatalf("%s: %d entries in the caller's tenant, want 1", action, len(got))
	}
	g := got[0]
	if g.resourceID != id || g.name != name || g.resourceType != string(rtype) || g.actor != f.userID {
		t.Errorf("%s entry = %+v, want id=%s name=%q type=%s actor=%s", action, g, id, name, rtype, f.userID)
	}
	if want := string(auditdom.SeverityForAction(action)); g.severity != want {
		t.Errorf("%s severity = %s, want %s", action, g.severity, want)
	}
	if n := len(f.entries(t, f.tenantB, action)); n != 0 {
		t.Errorf("%s: %d entries leaked into the other tenant", action, n)
	}
}

func (f *deleteAuditFixture) seedAsset(t *testing.T, tenant, name string) string {
	t.Helper()
	id := shared.NewID().String()
	if _, err := f.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'domain')`, id, tenant, name); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func TestAttackerProfileDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	h := NewAttackerProfileHandler(f.db, logger.NewNop())
	h.SetAuditService(f.auditSvc)
	id := shared.NewID().String()
	if _, err := f.db.Exec(`INSERT INTO attacker_profiles (id, tenant_id, name, profile_type) VALUES ($1,$2,'Insider X','malicious_insider')`, id, f.tenantA); err != nil {
		t.Fatal(err)
	}

	// Another tenant cannot delete it, and nothing is recorded for the refusal.
	rec := httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantB, nil, "id", id))
	if rec.Code != http.StatusNotFound || f.total(t, auditdom.ActionAttackerProfileDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionAttackerProfileDeleted))
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", id))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionAttackerProfileDeleted, auditdom.ResourceTypeAttackerProfile, id, "Insider X")

	// A second delete finds nothing and records nothing more.
	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", id))
	if rec.Code != http.StatusNotFound || f.total(t, auditdom.ActionAttackerProfileDeleted) != 1 {
		t.Fatalf("repeat delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionAttackerProfileDeleted))
	}
}

func TestBusinessServiceDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	h := NewBusinessServiceHandler(f.db, logger.NewNop())
	h.SetAuditService(f.auditSvc)
	id := shared.NewID().String()
	if _, err := f.db.Exec(`INSERT INTO business_services (id, tenant_id, name) VALUES ($1,$2,'Payments')`, id, f.tenantA); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantB, nil, "id", id))
	if rec.Code == http.StatusNoContent || f.total(t, auditdom.ActionBusinessServiceDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionBusinessServiceDeleted))
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", id))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionBusinessServiceDeleted, auditdom.ResourceTypeBusinessService, id, "Payments")
}

func TestBusinessUnitDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	svc := assetapp.NewBusinessUnitService(postgres.NewBusinessUnitRepository(f.pg), postgres.NewAssetRepository(f.pg), logger.NewNop())
	h := NewBusinessUnitHandler(svc, logger.NewNop())
	h.SetAuditService(f.auditSvc)
	id := shared.NewID().String()
	if _, err := f.db.Exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1,$2,'Retail')`, id, f.tenantA); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantB, nil, "id", id))
	if rec.Code != http.StatusNotFound || f.total(t, auditdom.ActionBusinessUnitDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionBusinessUnitDeleted))
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", id))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionBusinessUnitDeleted, auditdom.ResourceTypeBusinessUnit, id, "Retail")
}

func TestAssetGroupDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	svc := assetapp.NewAssetGroupService(postgres.NewAssetGroupRepository(f.pg), logger.NewNop())
	h := NewAssetGroupHandler(svc, validator.New(), logger.NewNop())
	h.SetAuditService(f.auditSvc)
	seed := func(tenant, name string) string {
		id := shared.NewID().String()
		if _, err := f.db.Exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1,$2,$3)`, id, tenant, name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	g1, g2 := seed(f.tenantA, "Prod web"), seed(f.tenantA, "Prod db")
	foreign := seed(f.tenantB, "Foreign")

	rec := httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", foreign))
	if rec.Code != http.StatusNotFound || f.total(t, auditdom.ActionAssetGroupDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionAssetGroupDeleted))
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "id", g1))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionAssetGroupDeleted, auditdom.ResourceTypeAssetGroup, g1, "Prod web")

	// Bulk: one entry for the group that was deleted, none for the other
	// tenant's group or the id that does not exist.
	missing := shared.NewID().String()
	body, _ := json.Marshal(map[string]any{"group_ids": []string{g2, foreign, missing}})
	rec = httptest.NewRecorder()
	h.BulkDelete(rec, f.req(http.MethodPost, "/x", f.tenantA, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk delete: %d %s", rec.Code, rec.Body.String())
	}
	got := f.entries(t, f.tenantA, auditdom.ActionAssetGroupDeleted)
	if len(got) != 2 {
		t.Fatalf("entries after bulk = %+v, want the single and the one bulk-deleted group", got)
	}
	var sawG2 bool
	for _, e := range got {
		if e.resourceID == g2 && e.name == "Prod db" {
			sawG2 = true
		}
		if e.resourceID == foreign || e.resourceID == missing {
			t.Errorf("an entry was recorded for a delete that did not happen: %+v", e)
		}
	}
	if !sawG2 {
		t.Errorf("no entry for the bulk-deleted group: %+v", got)
	}
	if f.total(t, auditdom.ActionAssetGroupDeleted) != 2 {
		t.Errorf("entries leaked into the other tenant")
	}
}

func TestAssetGroupBulkDelete_CappedAt100(t *testing.T) {
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = shared.NewID().String()
	}
	body, _ := json.Marshal(map[string]any{"group_ids": ids})
	h := NewAssetGroupHandler(nil, validator.New(), logger.NewNop())
	r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.BulkDelete(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("101 ids: status %d, want 400 (the service is nil, so no delete ran)", rec.Code)
	}
}

func TestAssetRelationshipDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	svc := assetapp.NewAssetRelationshipService(postgres.NewAssetRelationshipRepository(f.pg), postgres.NewAssetRepository(f.pg), logger.NewNop())
	h := NewAssetRelationshipHandler(svc, validator.New(), logger.NewNop())
	h.SetAuditService(f.auditSvc)
	src, dst := f.seedAsset(t, f.tenantA, "a.example.com"), f.seedAsset(t, f.tenantA, "b.example.com")
	id := shared.NewID().String()
	if _, err := f.db.Exec(`INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1,$2,$3,$4,'depends_on')`, id, f.tenantA, src, dst); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantB, nil, "relationshipId", id))
	if rec.Code != http.StatusNotFound || f.total(t, auditdom.ActionAssetRelationshipDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionAssetRelationshipDeleted))
	}

	rec = httptest.NewRecorder()
	h.Delete(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "relationshipId", id))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionAssetRelationshipDeleted, auditdom.ResourceTypeAssetRelationship, id,
		"a.example.com -> depends_on -> b.example.com")
}

func TestPentestTemplateDelete_IsAudited(t *testing.T) {
	f := newDeleteAuditFixture(t)
	repo := postgres.NewPentestTemplateRepository(f.pg)
	svc := compliance.NewPentestService(nil, nil, nil, repo, nil, logger.NewNop())
	h := NewPentestHandler(svc, nil, validator.New(), logger.NewNop())
	h.SetAuditService(f.auditSvc)
	tid, _ := shared.IDFromString(f.tenantA)
	tmpl, err := pentest.NewTemplate(tid, "SQL injection", pentest.FindingSeverity("high"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(context.Background(), tmpl); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	id := tmpl.ID().String()

	rec := httptest.NewRecorder()
	h.DeleteTemplate(rec, f.req(http.MethodDelete, "/x", f.tenantB, nil, "templateId", id))
	if rec.Code == http.StatusNoContent || f.total(t, auditdom.ActionPentestTemplateDeleted) != 0 {
		t.Fatalf("cross-tenant delete: status %d, entries %d", rec.Code, f.total(t, auditdom.ActionPentestTemplateDeleted))
	}

	rec = httptest.NewRecorder()
	h.DeleteTemplate(rec, f.req(http.MethodDelete, "/x", f.tenantA, nil, "templateId", id))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	f.wantOne(t, auditdom.ActionPentestTemplateDeleted, auditdom.ResourceTypePentestTemplate, id, "SQL injection")
}

// fakeDedupStore stands in for the review repository.
type fakeDedupStore struct {
	report *postgres.MergeReport
	err    error
}

func (s fakeDedupStore) ListPendingReviews(context.Context, string, *shared.DataScope) ([]postgres.AssetDedupReview, error) {
	return nil, nil
}
func (s fakeDedupStore) ApproveAndMergeReport(context.Context, string, string, string, *shared.DataScope) (*postgres.MergeReport, error) {
	return s.report, s.err
}
func (s fakeDedupStore) RejectReview(context.Context, string, string, string, *shared.DataScope) error {
	return nil
}
func (s fakeDedupStore) GetMergeLog(context.Context, string, string, int, *shared.DataScope) ([]map[string]any, int, error) {
	return nil, 0, nil
}

func TestDedupApprove_AuditsEveryDeletedAsset(t *testing.T) {
	tenant := shared.NewID().String()
	run := func(store fakeDedupStore) (*httptest.ResponseRecorder, *fakeAuditRepo) {
		repo := &fakeAuditRepo{}
		h := NewAdminDedupHandler(nil, logger.NewNop())
		h.repo = store
		h.SetAuditService(auditapp.NewAuditService(repo, logger.NewNop()))
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, tenant))
		r.SetPathValue("id", "rev-1")
		rec := httptest.NewRecorder()
		h.Approve(rec, r)
		return rec, repo
	}

	rec, repo := run(fakeDedupStore{report: &postgres.MergeReport{
		ReviewID: "rev-1", KeptAssetID: "keep-1", KeptName: "example.com",
		MergedAssets: []postgres.MergedAsset{{ID: "m1", Name: "EXAMPLE.com"}, {ID: "m2", Name: "example.com."}},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if len(repo.logs) != 2 {
		t.Fatalf("%d audit entries, want one per deleted asset (2)", len(repo.logs))
	}
	for i, want := range []struct{ id, name string }{{"m1", "EXAMPLE.com"}, {"m2", "example.com."}} {
		l := repo.logs[i]
		if l.Action() != auditdom.ActionAssetDuplicateMerged || l.ResourceType() != auditdom.ResourceTypeAsset ||
			l.ResourceID() != want.id || l.ResourceName() != want.name ||
			l.TenantID() == nil || l.TenantID().String() != tenant {
			t.Errorf("entry %d = %s %s %s %q tenant=%v", i, l.Action(), l.ResourceType(), l.ResourceID(), l.ResourceName(), l.TenantID())
		}
		if l.Severity() != auditdom.SeverityHigh {
			t.Errorf("entry %d severity %s, want high", i, l.Severity())
		}
	}

	for name, err := range map[string]error{
		"not found": fmt.Errorf("%w: review", shared.ErrNotFound),
		"conflict":  fmt.Errorf("%w: not pending", shared.ErrConflict),
		"failed":    errors.New("tx failed"),
	} {
		rec, repo := run(fakeDedupStore{err: err})
		if rec.Code == http.StatusOK || len(repo.logs) != 0 {
			t.Errorf("%s: status %d, %d entries; a refused or failed merge records nothing", name, rec.Code, len(repo.logs))
		}
	}
}

func TestDeletedActionsAreValidAndRegistered(t *testing.T) {
	for _, a := range []auditdom.Action{
		auditdom.ActionAssetGroupDeleted, auditdom.ActionBusinessUnitDeleted, auditdom.ActionBusinessServiceDeleted,
		auditdom.ActionAttackerProfileDeleted, auditdom.ActionPentestTemplateDeleted,
		auditdom.ActionAssetRelationshipDeleted, auditdom.ActionAssetDuplicateMerged,
	} {
		if !a.IsValid() || a.Category() == "" || !strings.Contains(string(a), ".") {
			t.Errorf("%s: valid=%v category=%q", a, a.IsValid(), a.Category())
		}
	}
	for _, r := range []auditdom.ResourceType{
		auditdom.ResourceTypeAssetGroup, auditdom.ResourceTypeBusinessUnit, auditdom.ResourceTypeBusinessService,
		auditdom.ResourceTypeAttackerProfile, auditdom.ResourceTypePentestTemplate, auditdom.ResourceTypeAssetRelationship,
	} {
		if !r.IsValid() {
			t.Errorf("resource type %s rejected", r)
		}
	}
}
