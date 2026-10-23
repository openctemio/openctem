package integration

// GET /api/v1/findings/{id}/identity against a migrated database: the
// recipe and field names of the key, the reporting tools and the merged
// duplicates, each filtered by the caller's data scope; tenant isolation;
// and the recipe columns kept by the re-sighting upsert and set by a re-key.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type findingIdentityFixture struct {
	db                         *sql.DB
	tenant, other              shared.ID
	inScope, outScope          shared.ID // assets
	admin, member, otherMember shared.ID
	survivor, near, far        shared.ID // findings: near on inScope, far on outScope
	key                        vulnerability.IdentityKey
	h                          *handler.VulnerabilityHandler
	repo                       *postgres.FindingRepository
}

func newFindingIdentityFixture(t *testing.T) *findingIdentityFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &findingIdentityFixture{
		db:      db,
		tenant:  createTestTenant(t, db, "ident-explain"),
		other:   createTestTenant(t, db, "ident-explain-other"),
		inScope: shared.NewID(), outScope: shared.NewID(),
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	for _, a := range []shared.ID{f.inScope, f.outScope} {
		f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
			a.String(), f.tenant.String(), "ident-"+a.String())
	}
	f.admin, f.member, f.otherMember = seedActUser(t, db), seedActUser(t, db), seedActUser(t, db)
	f.exec(t, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		f.member.String(), f.tenant.String(), f.inScope.String())

	pg := &postgres.DB{DB: db}
	f.repo = postgres.NewFindingRepository(pg)
	ctx := context.Background()

	var ok bool
	f.key, ok = vulnerability.SCAIdentity(f.inScope.String(), "pkg:npm/lodash@4.17.20", "npm", "lodash", "CVE-2021-23337", "")
	if !ok {
		t.Fatal("no SCA key")
	}
	s, err := vulnerability.NewFinding(f.tenant, f.inScope, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "lodash")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetIdentity(f.key); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Create(ctx, s); err != nil {
		t.Fatalf("create survivor: %v", err)
	}
	f.survivor = s.ID()

	tomb := func(asset shared.ID, tool, reason string) shared.ID {
		id := shared.NewID()
		f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, duplicate_of)
			VALUES ($1, $2, $3, 'sca', $4, 'm', 'high', $5, 'duplicate', $6)`,
			id.String(), f.tenant.String(), asset.String(), tool, "dup:"+id.String(), f.survivor.String())
		f.exec(t, `INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
			VALUES ($1, $2, 'duplicate_marked', 'system', jsonb_build_object('duplicate_of', $3::text, 'reason', $4::text), $4, 'merged')`,
			f.tenant.String(), id.String(), f.survivor.String(), reason)
		return id
	}
	f.near = tomb(f.inScope, "grype", "manual")
	f.far = tomb(f.outScope, "far-scanner", "asset_merge")

	receipt := shared.NewID()
	f.exec(t, `INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, tool_name) VALUES ($1, $2, 'sensor', $3, 'osv-scanner')`,
		receipt.String(), f.tenant.String(), receipt.String())
	f.exec(t, `INSERT INTO finding_ingest_actions (tenant_id, receipt_id, finding_id, action) VALUES ($1, $2, $3, 'still_detected')`,
		f.tenant.String(), receipt.String(), f.survivor.String())

	enf := datascope.New(postgres.NewDataScopeRepository(pg), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	svc := finding.NewVulnerabilityService(nil, f.repo, logger.NewNop())
	svc.SetDataScope(enf)
	f.h = handler.NewVulnerabilityHandler(svc, nil, logger.NewNop())
	return f
}

func (f *findingIdentityFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

// get calls the handler as user in tenant.
func (f *findingIdentityFixture) get(t *testing.T, tenant, user shared.ID, admin bool, findingID shared.ID) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/identity", nil)
	req.SetPathValue("id", findingID.String())
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, user.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	ctx = asCaller(ctx, datascope.Caller{UserID: user.String(), IsAdmin: admin})
	rec := httptest.NewRecorder()
	f.h.GetFindingIdentity(rec, req.WithContext(ctx))
	return rec.Code, rec.Body.String()
}

func decodeFindingIdentity(t *testing.T, body string) handler.FindingIdentityResponse {
	t.Helper()
	var out handler.FindingIdentityResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

func findingIdentityTools(r handler.FindingIdentityResponse) []string {
	out := make([]string, 0, len(r.Sources))
	for _, s := range r.Sources {
		out = append(out, s.Tool)
	}
	return out
}

func TestFindingIdentity_AdminSeesRecipeSourcesAndMerged(t *testing.T) {
	f := newFindingIdentityFixture(t)
	code, body := f.get(t, f.tenant, f.admin, true, f.survivor)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	r := decodeFindingIdentity(t, body)
	if r.Algo != "v2/sca" || r.Version != 2 || r.Derived || r.Legacy ||
		!reflect.DeepEqual(r.Fields, []string{"asset", "component", "vuln"}) {
		t.Errorf("recipe = %+v", r)
	}
	tools := strings.Join(findingIdentityTools(r), ",")
	for _, want := range []string{"trivy", "osv-scanner", "grype", "far-scanner"} {
		if !strings.Contains(tools, want) {
			t.Errorf("sources %q miss %q", tools, want)
		}
	}
	if len(r.Merged) != 2 {
		t.Fatalf("merged = %+v, want 2", r.Merged)
	}
	reasons := map[string]string{}
	for _, m := range r.Merged {
		reasons[m.ID] = m.Reason
	}
	if reasons[f.near.String()] != "manual" || reasons[f.far.String()] != "asset_merge" {
		t.Errorf("reasons = %v", reasons)
	}
	// Names only: no value of the key, no fingerprint.
	for _, fld := range f.key.Fields {
		if strings.Contains(body, fld.Value) && fld.Name != "asset" {
			t.Errorf("response carries the value of %q: %s", fld.Name, body)
		}
	}
	if strings.Contains(body, f.key.Fingerprint()) || strings.Contains(body, "fingerprint") || strings.Contains(body, "identity_key") {
		t.Errorf("response carries key material: %s", body)
	}
}

// A restricted member sees the finding on their asset, but not the tombstone
// on an asset outside their scope, nor its tool, nor a count of it.
func TestFindingIdentity_RestrictedMemberSeesOnlyInScopeDuplicates(t *testing.T) {
	f := newFindingIdentityFixture(t)
	code, body := f.get(t, f.tenant, f.member, false, f.survivor)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	r := decodeFindingIdentity(t, body)
	if len(r.Merged) != 1 || r.Merged[0].ID != f.near.String() {
		t.Errorf("merged = %+v, want only the in-scope duplicate", r.Merged)
	}
	if strings.Contains(body, f.far.String()) || strings.Contains(body, "far-scanner") {
		t.Errorf("out-of-scope duplicate leaked: %s", body)
	}

	// A member without the asset: 404, like GET /findings/{id}.
	if code, body := f.get(t, f.tenant, f.otherMember, false, f.survivor); code != http.StatusNotFound {
		t.Errorf("member without the asset: status %d, want 404: %s", code, body)
	}
}

func TestFindingIdentity_OtherTenantGets404(t *testing.T) {
	f := newFindingIdentityFixture(t)
	if code, body := f.get(t, f.other, f.admin, true, f.survivor); code != http.StatusNotFound {
		t.Errorf("tenant B: status %d, want 404: %s", code, body)
	}
}

func readFindingRecipe(t *testing.T, db *sql.DB, tenant, id shared.ID) (sql.NullString, []string) {
	t.Helper()
	var algo sql.NullString
	var fields sql.NullString
	if err := db.QueryRow(`SELECT identity_algo, array_to_string(identity_fields, ',') FROM findings WHERE tenant_id = $1 AND id = $2`,
		tenant.String(), id.String()).Scan(&algo, &fields); err != nil {
		t.Fatalf("read recipe: %v", err)
	}
	if !fields.Valid || fields.String == "" {
		return algo, nil
	}
	return algo, strings.Split(fields.String, ",")
}

// The re-sighting upsert keeps the recorded recipe; a row without one takes
// the incoming recipe only from a sighting keyed by the same recipe version.
func TestFindingIdentity_RecipeSurvivesUpsertAndFillsLegacyRow(t *testing.T) {
	f := newFindingIdentityFixture(t)
	ctx := context.Background()

	again, _ := vulnerability.NewFinding(f.tenant, f.inScope, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "lodash")
	again.SetFingerprint(f.key.Fingerprint()) // same key, recipe not named
	if _, err := f.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{again}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if algo, fields := readFindingRecipe(t, f.db, f.tenant, f.survivor); algo.String != "v2/sca" || !reflect.DeepEqual(fields, []string{"asset", "component", "vuln"}) {
		t.Errorf("after upsert: %v %v, want v2/sca kept", algo, fields)
	}

	// A version-1 row from before the columns: a version-1 sighting fills it.
	legacy, _ := vulnerability.NewFinding(f.tenant, f.inScope, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityLow, "x")
	legacy.SetFingerprint(strings.Repeat("ab", 32))
	if err := f.repo.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if algo, _ := readFindingRecipe(t, f.db, f.tenant, legacy.ID()); algo.Valid {
		t.Fatalf("legacy row has a recipe: %v", algo)
	}
	code, body := f.get(t, f.tenant, f.admin, true, legacy.ID())
	if r := decodeFindingIdentity(t, body); code != http.StatusOK || !r.Legacy || r.Algo != "" {
		t.Errorf("legacy explanation: %d %+v", code, r)
	}
	sighting, _ := vulnerability.NewFinding(f.tenant, f.inScope, vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityLow, "x")
	sighting.SetFingerprint(legacy.Fingerprint())
	sighting.MarkIngestV1Key()
	if _, err := f.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{sighting}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if algo, fields := readFindingRecipe(t, f.db, f.tenant, legacy.ID()); algo.String != vulnerability.IdentityAlgoIngestV1 || fields != nil {
		t.Errorf("legacy row after a v1 sighting: %v %v", algo, fields)
	}

	// A version-1 sighting landing on a version-2 row without a recipe
	// (keyed before the columns) must not label it version 1.
	f.exec(t, `UPDATE findings SET identity_algo = NULL, identity_fields = NULL WHERE id = $1`, f.survivor.String())
	v1, _ := vulnerability.NewFinding(f.tenant, f.inScope, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "lodash")
	v1.SetFingerprint(f.key.Fingerprint())
	v1.MarkIngestV1Key()
	if _, err := f.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{v1}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if algo, _ := readFindingRecipe(t, f.db, f.tenant, f.survivor); algo.Valid {
		t.Errorf("version-2 row labeled %v by a version-1 sighting", algo)
	}
	code, body = f.get(t, f.tenant, f.admin, true, f.survivor)
	if r := decodeFindingIdentity(t, body); code != http.StatusOK || !r.Derived || r.Algo != "v2/sca" {
		t.Errorf("derived explanation: %d %+v", code, r)
	}
}

// The re-key job writes the recipe with the new key.
func TestFindingIdentity_RekeySetsRecipe(t *testing.T) {
	f := newFindingIdentityFixture(t)
	ctx := context.Background()
	old, _ := vulnerability.NewFinding(f.tenant, f.outScope, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	old.SetFingerprint(strings.Repeat("cd", 32))
	old.MarkIngestV1Key()
	if err := f.repo.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if algo, _ := readFindingRecipe(t, f.db, f.tenant, old.ID()); algo.String != vulnerability.IdentityAlgoIngestV1 {
		t.Fatalf("created with %v", algo)
	}
	k, ok := vulnerability.SCAIdentity(f.outScope.String(), "pkg:npm/minimist@1.2.0", "npm", "minimist", "CVE-2021-44906", "")
	if !ok {
		t.Fatal("no key")
	}
	res, err := postgres.NewFindingRekeyRepository(&postgres.DB{DB: f.db}).Rekey(ctx, f.tenant, old.ID().String(), old.Fingerprint(), k)
	if err != nil || res.Outcome != vulnerability.RekeyOutcomeRekeyed {
		t.Fatalf("rekey: %+v %v", res, err)
	}
	if algo, fields := readFindingRecipe(t, f.db, f.tenant, old.ID()); algo.String != "v2/sca" || !reflect.DeepEqual(fields, []string{"asset", "component", "vuln"}) {
		t.Errorf("after re-key: %v %v", algo, fields)
	}
}
