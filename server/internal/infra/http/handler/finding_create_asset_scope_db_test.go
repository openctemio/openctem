package handler

// POST /findings against real Postgres: the asset_id (and branch_id) a caller
// sends must be a live asset of the caller's tenant that the caller may see.
// findings.asset_id references assets(id) alone, so before the check a member
// of tenant A could attach a finding to tenant B's asset: B could then no
// longer delete that asset, and the refusal disclosed the foreign count.
// Research doc 21b, C1 (same class as L-02, fixed for pentest in #973).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestCreateFinding_AssetTenantAndScope_DB(t *testing.T) {
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

	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	admin, scoped := shared.NewID().String(), shared.NewID().String()
	inScope, outScope, deleted, foreign := shared.NewID().String(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'fca', $2)`, tn, "fca-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'fca')`, u, u+"@fca.test")
	}
	for id, tn := range map[string]string{inScope: tenantA, outScope: tenantA, deleted: tenantA, foreign: tenantB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'repository', 'public', 'high')`,
			id, tn, "fca-"+id)
		exec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, id)
	}
	exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted)
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenantA, inScope)
	branchOf := map[string]string{}
	for _, a := range []string{inScope, outScope, foreign} {
		b := shared.NewID().String()
		exec(`INSERT INTO repository_branches (id, repository_id, name) VALUES ($1, $2, 'main')`, b, a)
		branchOf[a] = b
	}

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	svc.SetDataScope(enforcer)
	svc.SetBranchLookup(postgres.NewBranchRepository(db))
	h := NewVulnerabilityHandler(svc, validator.New(), logger.NewNop())

	n := 0
	create := func(user string, isAdmin bool, assetID, branchID string) (int, string) {
		t.Helper()
		n++
		body := map[string]any{
			"asset_id": assetID, "source": "manual", "tool_name": "fca", "severity": "high",
			"message": "fca finding " + string(rune('a'+n)),
		}
		if branchID != "" {
			body["branch_id"] = branchID
		}
		raw, _ := json.Marshal(body)
		r := pentestDBRequest(http.MethodPost, "/", tenantA, string(raw), nil)
		c := context.WithValue(r.Context(), middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, isAdmin)
		w := httptest.NewRecorder()
		h.CreateFinding(w, r.WithContext(c))
		return w.Code, w.Body.String()
	}

	// Cross-tenant: refused for an admin too, identical to an unknown id.
	fStatus, fBody := create(admin, true, foreign, "")
	if fStatus != http.StatusNotFound {
		t.Errorf("finding on a tenant B asset = %d, want 404 (%s)", fStatus, fBody)
	}
	uStatus, uBody := create(admin, true, shared.NewID().String(), "")
	if uStatus != fStatus || uBody != fBody {
		t.Errorf("foreign id answered %d %q, unknown id %d %q: must be identical", fStatus, fBody, uStatus, uBody)
	}
	if status, _ := create(admin, true, deleted, ""); status != http.StatusNotFound {
		t.Errorf("finding on a deleted asset = %d, want 404", status)
	}
	// Restricted member, own tenant but outside their data scope: refused.
	if status, body := create(scoped, false, outScope, ""); status != http.StatusNotFound {
		t.Errorf("scoped member, out-of-scope asset = %d, want 404 (%s)", status, body)
	}
	// A branch must belong to the finding's asset: another tenant's branch,
	// or another asset's branch in the same tenant, is refused.
	if status, body := create(admin, true, inScope, branchOf[foreign]); status != http.StatusNotFound {
		t.Errorf("tenant B branch = %d, want 404 (%s)", status, body)
	}
	if status, body := create(admin, true, inScope, branchOf[outScope]); status != http.StatusNotFound {
		t.Errorf("branch of another asset = %d, want 404 (%s)", status, body)
	}
	// Allowed: in-scope member, admin on an own asset, own branch.
	if status, body := create(scoped, false, inScope, ""); status != http.StatusCreated {
		t.Errorf("scoped member, in-scope asset = %d, want 201 (%s)", status, body)
	}
	if status, body := create(admin, true, outScope, ""); status != http.StatusCreated {
		t.Errorf("admin, own-tenant asset = %d, want 201 (%s)", status, body)
	}
	if status, body := create(scoped, false, inScope, branchOf[inScope]); status != http.StatusCreated {
		t.Errorf("own branch = %d, want 201 (%s)", status, body)
	}

	var stray int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE asset_id = ANY($1::uuid[]) OR branch_id = $2`,
		"{"+foreign+","+deleted+"}", branchOf[foreign]).Scan(&stray); err != nil {
		t.Fatal(err)
	}
	if stray != 0 {
		t.Errorf("%d finding(s) stored on a foreign or deleted asset or branch", stray)
	}
	var foreignBranchCount int
	if err := raw.QueryRowContext(ctx, `SELECT findings_total FROM repository_branches WHERE id = $1`, branchOf[foreign]).Scan(&foreignBranchCount); err != nil {
		t.Fatal(err)
	}
	if foreignBranchCount != 0 {
		t.Errorf("tenant B branch counter = %d, want 0", foreignBranchCount)
	}
}

// TestAssetDelete_FindingCountIsTenantScoped_DB: a finding another tenant
// pointed at this tenant's asset (rows written before the create check, or
// through any other path) neither blocks the delete nor has its count
// disclosed; this tenant's own findings still refuse the delete, counted
// alone.
func TestAssetDelete_FindingCountIsTenantScoped_DB(t *testing.T) {
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
	victim, attacker := shared.NewID().String(), shared.NewID().String()
	for _, tn := range []string{victim, attacker} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'fcd', $2)`, tn, "fcd-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{victim, attacker} {
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
	})
	onlyForeign, mixed := shared.NewID().String(), shared.NewID().String()
	for _, a := range []string{onlyForeign, mixed} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			a, victim, "fcd-"+a+".example.com")
	}
	seedFinding := func(tenant, assetID, fp string) {
		exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, 'manual', 'fcd', 'high', 'fcd', $3)`, tenant, assetID, fp)
	}
	// Simulates a pre-existing cross-tenant row. Once the composite FK
	// backstop is in place the database itself refuses it, which is the
	// stronger guarantee, and there is nothing left to count.
	if _, err := raw.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
	      VALUES ($1, $2, 'manual', 'fcd', 'high', 'fcd', $3)`, attacker, onlyForeign, "fcd-f1-"+onlyForeign); err != nil {
		if !strings.Contains(err.Error(), "foreign key") {
			t.Fatalf("seed cross-tenant finding: %v", err)
		}
		return
	}
	seedFinding(attacker, mixed, "fcd-f2-"+mixed)
	seedFinding(attacker, mixed, "fcd-f3-"+mixed)
	seedFinding(victim, mixed, "fcd-v1-"+mixed)

	repo := postgres.NewAssetRepository(&postgres.DB{DB: raw})
	vid := shared.MustIDFromString(victim)

	if err := repo.Delete(ctx, vid, shared.MustIDFromString(onlyForeign), nil); err != nil {
		t.Errorf("delete of an asset only a foreign finding points at = %v, want nil", err)
	}
	err = repo.Delete(ctx, vid, shared.MustIDFromString(mixed), nil)
	var hf *asset.HasFindingsError
	if !errors.As(err, &hf) {
		t.Fatalf("delete of an asset with an own finding = %v, want HasFindingsError", err)
	}
	if hf.FindingCount != 1 {
		t.Errorf("refusal reports %d findings, want 1 (own tenant only)", hf.FindingCount)
	}
}
