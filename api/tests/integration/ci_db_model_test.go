package integration

// CI data model (migration 001113, docs/rfcs/RFC-051-ci-runner-identity-and-gate.md
// "Data model"): gate policies reference their repository or business unit
// with foreign keys and follow a merged repository; trust-configuration
// references carry the tenant; break-glass stores no email; retention.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestCIGatePolicyScopeKeys(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	tenant := createTestTenant(t, db, "cigate")
	other := createTestTenant(t, db, "cigate-other")
	keep := createTestAsset(t, db, tenant, "keep-cigate")
	merge := createTestAsset(t, db, tenant, "merge-cigate")
	both := createTestAsset(t, db, tenant, "both-cigate")
	foreign := createTestAsset(t, db, other, "foreign-cigate")
	T := tenant.String()
	exec := func(q string, args ...any) error {
		_, err := db.ExecContext(ctx, q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
		return n
	}
	policy := func(scope string, repo, unit any) error {
		return exec(`INSERT INTO ci_gate_policies (id, tenant_id, scope_type, repository_asset_id, business_unit_id)
			VALUES ($1, $2, $3, $4, $5)`, shared.NewID().String(), T, scope, repo, unit)
	}

	// The scope column must match the scope type; a foreign repository or
	// business unit is refused by the foreign key.
	if err := policy("repository", nil, nil); err == nil {
		t.Fatal("a repository policy without a repository was accepted")
	}
	if err := policy("tenant", keep.String(), nil); err == nil {
		t.Fatal("a tenant policy naming a repository was accepted")
	}
	if err := policy("repository", foreign.String(), nil); err == nil {
		t.Fatal("a policy on another tenant's repository was accepted")
	}
	must(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'bu-cigate')`, shared.NewID().String(), other.String())
	var foreignUnit string
	_ = db.QueryRowContext(ctx, `SELECT id FROM business_units WHERE tenant_id = $1`, other.String()).Scan(&foreignUnit)
	if err := policy("business_unit", nil, foreignUnit); err == nil {
		t.Fatal("a policy on another tenant's business unit was accepted")
	}

	// The repository layer reads the scope back from the right column.
	repo := postgres.NewCIRunRepository(&postgres.DB{DB: db})
	unit := shared.NewID()
	must(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'bu-cigate')`, unit.String(), T)
	must(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
		shared.NewID().String(), T, unit.String(), merge.String())
	for _, p := range []*cirun.GatePolicy{
		{ScopeType: cirun.ScopeRepository, ScopeID: &merge},
		{ScopeType: cirun.ScopeRepository, ScopeID: &both},
		{ScopeType: cirun.ScopeBusinessUnit, ScopeID: &unit},
	} {
		p.ID, p.TenantID, p.Enabled, p.Mode, p.FailOnSeverity, p.CreatedAt = shared.NewID(), tenant, true, cirun.ModeEnforce, "high", time.Now()
		if err := repo.CreateGatePolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.GatePoliciesFor(ctx, tenant, merge)
	if err != nil || len(got) != 2 {
		t.Fatalf("policies for the repository: %d %v", len(got), err)
	}
	for _, p := range got {
		if p.ScopeID == nil || (*p.ScopeID != merge && *p.ScopeID != unit) {
			t.Fatalf("scope read back = %+v", p)
		}
	}

	// Merge: the merged repository's policy follows it to the kept one.
	review := shared.NewID().String()
	must(`INSERT INTO asset_dedup_review (id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name,
		merge_asset_ids, merge_asset_names, status) VALUES ($1, $2, 'keep', 'repository', $3, 'keep', ARRAY[$4::uuid], ARRAY['merge'], 'pending')`,
		review, T, keep.String(), merge.String())
	reviewer := shared.NewID().String()
	must(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'ci merge test')`, reviewer, "cimerge-"+reviewer+"@example.test")
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, reviewer) })
	if err := postgres.NewAssetDedupRepository(&postgres.DB{DB: db}).ApproveAndMerge(ctx, T, review, reviewer, nil); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if n := count(`SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1 AND repository_asset_id = $2`, T, keep.String()); n != 1 {
		t.Fatalf("policy did not follow the merged repository (%d on the kept one)", n)
	}
	// Delete: a repository's or business unit's policy goes with it.
	must(`DELETE FROM assets WHERE tenant_id = $1 AND id = $2`, T, both.String())
	must(`DELETE FROM business_units WHERE tenant_id = $1 AND id = $2`, T, unit.String())
	if n := count(`SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1`, T); n != 1 {
		t.Fatalf("policies after deleting a repository and a business unit: %d, want 1", n)
	}
}

func TestCITrustReferencesAndOverrideCreator(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	const sha = "6666666666666666666666666666666666666666"
	code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", "main", sha, nil))
	if code != http.StatusCreated {
		t.Fatalf("exchange: %d %v", code, ex)
	}
	runID := ex["run_id"].(string)

	// Another tenant's trust configuration cannot be referenced.
	otherCfg := r.trust(r.other, cirun.Rules{Owners: []string{"acme"}})
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET trust_config_id = $3 WHERE tenant_id = $1 AND id = $2`,
		r.tenant.String(), runID, otherCfg.ID.String()); err == nil {
		t.Fatal("a run now references another tenant's trust configuration")
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_pipelines SET trust_config_id = $2 WHERE tenant_id = $1`,
		r.tenant.String(), otherCfg.ID.String()); err == nil {
		t.Fatal("a pipeline now references another tenant's trust configuration")
	}

	// Break-glass: the creator is a user id; the email is read, not stored.
	user := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'ci admin')`,
		user.String(), "ci-admin-"+user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String())
	})
	assetID, _ := shared.IDFromString(ex["repository_asset_id"].(string))
	o, err := r.svc.CreateOverride(ctx, r.tenant, cirunapp.OverrideInput{RepositoryAssetID: assetID, CommitSHA: sha[:12],
		Reason: "release blocked by a known false positive"}, cirunapp.Actor{UserID: user.String(), Email: "ignored@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.repo.GetOverride(ctx, r.tenant, o.ID)
	if err != nil || !strings.HasPrefix(got.CreatedByEmail, "ci-admin-") {
		t.Fatalf("creator read back: %+v %v", got, err)
	}
	var cols int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'ci_gate_overrides' AND column_name = 'created_by_email'`).Scan(&cols)
	if cols != 0 {
		t.Fatal("ci_gate_overrides still stores an email")
	}
	// The verdict (printed in CI logs) names no one.
	if _, v := r.post("/api/v1/ci/runs/"+runID+"/evaluate", ex["token"].(string), nil); strings.Contains(strings.ToLower(
		mustJSON(t, v)), "ci-admin-") {
		t.Fatalf("the verdict names the break-glass creator: %v", v)
	}

	// Deleting the trust configuration keeps the run and its pipeline as
	// history.
	if err := r.svc.DeleteTrustConfig(ctx, r.tenant, cfg.ID, cirunapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	var runs, pipes int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND trust_config_id IS NULL`, r.tenant.String()).Scan(&runs)
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1 AND trust_config_id IS NULL`, r.tenant.String()).Scan(&pipes)
	if runs != 1 || pipes != 1 {
		t.Fatalf("after deleting the trust configuration: %d runs, %d pipelines kept", runs, pipes)
	}
}

func TestCIRetention(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	exchange := func(ref, sha string) string {
		t.Helper()
		code, ex := r.exchange(r.tenant, r.idp.token(t, cfg.Audience, "acme/api", ref, sha, nil))
		if code != http.StatusCreated {
			t.Fatalf("exchange: %d %v", code, ex)
		}
		return ex["run_id"].(string)
	}
	// Five runs of one pipeline: the two oldest on the default branch.
	ids := []string{
		exchange("main", "1000000000000000000000000000000000000001"),
		exchange("main", "1000000000000000000000000000000000000002"),
		exchange("feature/a", "1000000000000000000000000000000000000003"),
		exchange("feature/b", "1000000000000000000000000000000000000004"),
		exchange("feature/c", "1000000000000000000000000000000000000005"),
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := r.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	now := time.Now().UTC()
	// Ages: 500, 450, 420, 100 and 10 days; every run sighted a fingerprint;
	// every token expired yesterday.
	for i, days := range []int{500, 450, 420, 100, 10} {
		exec(`UPDATE ci_runs SET created_at = $3, token_expires_at = $4 WHERE tenant_id = $1 AND id = $2`,
			r.tenant.String(), ids[i], now.AddDate(0, 0, -days), now.AddDate(0, 0, -1))
		exec(`INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint) VALUES ($1, $2, 'fp')`, r.tenant.String(), ids[i])
	}
	// The other tenant's old run is untouched by this tenant's pass.
	otherCfg := r.trust(r.other, cirun.Rules{Owners: []string{"acme"}})
	code, ex := r.exchange(r.other, r.idp.token(t, otherCfg.Audience, "acme/api", "feature/x", "2000000000000000000000000000000000000001", nil))
	if code != http.StatusCreated {
		t.Fatalf("other exchange: %d", code)
	}
	otherRun := ex["run_id"].(string)
	exec(`UPDATE ci_runs SET created_at = $2 WHERE id = $1`, otherRun, now.AddDate(0, 0, -500))

	job := cirunapp.NewRetentionJob(r.repo, logger.NewNop())
	res, err := job.PurgeTenant(ctx, r.tenant)
	if err != nil {
		t.Fatal(err)
	}
	exists := func(id string) bool {
		var n int
		_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE id = $1`, id).Scan(&n)
		return n == 1
	}
	findings := func(id string) int {
		var n int
		_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_run_findings WHERE run_id = $1`, id).Scan(&n)
		return n
	}
	// 500 d: older than 400 d, not kept -> gone. 450 d: the latest
	// default-branch run -> kept with its findings. 420 d: gone. 100 d: run
	// kept, findings purged. 10 d (the latest run): kept with findings.
	if exists(ids[0]) || !exists(ids[1]) || exists(ids[2]) || !exists(ids[3]) || !exists(ids[4]) {
		t.Fatalf("runs kept: %v %v %v %v %v", exists(ids[0]), exists(ids[1]), exists(ids[2]), exists(ids[3]), exists(ids[4]))
	}
	if findings(ids[1]) != 1 || findings(ids[3]) != 0 || findings(ids[4]) != 1 {
		t.Fatalf("findings kept: %d %d %d", findings(ids[1]), findings(ids[3]), findings(ids[4]))
	}
	var hashes int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND token_hash IS NOT NULL`, r.tenant.String()).Scan(&hashes)
	if hashes != 0 || res.RunsPurged != 2 {
		t.Fatalf("token hashes left %d, runs purged %d", hashes, res.RunsPurged)
	}
	if !exists(otherRun) {
		t.Fatal("another tenant's run was purged")
	}
	// The full pass walks both tenants; the other tenant's only run is its
	// pipeline's latest and is kept.
	if _, err := job.Run(ctx); err != nil || !exists(otherRun) {
		t.Fatalf("full pass: %v, other run kept %v", err, exists(otherRun))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
