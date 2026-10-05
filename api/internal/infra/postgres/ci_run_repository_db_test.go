package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CI runs against the real schema (migration 001058): tenant isolation on
// every read and write, the data scope on the run list, token lookups that
// honor expiry, OIDC replay, the per-run findings cap, overrides by commit
// prefix, and policies through business units. Requires DATABASE_URL.
func TestCIRunRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	repoA := seedTestAsset(ctx, t, db, tenant)
	repoB := seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()

	newRun := func(tid, asset shared.ID, exp time.Time) (*cirun.Run, string) {
		tok, hash, err := cirun.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		r := &cirun.Run{ID: shared.NewID(), TenantID: tid, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/api", Ref: "refs/heads/main", Branch: "main",
			CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp,
			CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatalf("create run: %v", err)
		}
		return r, tok
	}
	runA, tokA := newRun(tenant, repoA, now.Add(10*time.Minute))
	runB, _ := newRun(tenant, repoB, now.Add(10*time.Minute))
	_, tokExpired := newRun(tenant, repoA, now.Add(-time.Second))

	// Token lookups: unexpired only.
	if got, err := repo.GetRunByTokenHash(ctx, cirun.HashToken(tokA), now); err != nil || got.ID != runA.ID {
		t.Fatalf("token lookup: %v %v", got, err)
	}
	if _, err := repo.GetRunByTokenHash(ctx, cirun.HashToken(tokExpired), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}
	// Cross-tenant: not found, not listed.
	if _, err := repo.GetRun(ctx, other, runA.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if runs, total, err := repo.ListRuns(ctx, other, cirun.RunFilter{}); err != nil || total != 0 || len(runs) != 0 {
		t.Fatalf("cross-tenant list: %d %v", total, err)
	}
	if err := repo.SaveVerdict(ctx, other, runA.ID, cirun.VerdictPass, []byte(`{}`), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant verdict: %v", err)
	}
	// A run cannot point at another tenant's asset (composite foreign key).
	otherAsset := seedTestAsset(ctx, t, db, other)
	tok, hash, _ := cirun.NewToken()
	_ = tok
	bad := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: otherAsset, Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Repository: "x", Status: cirun.StatusRunning, TokenHash: hash, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, bad); err == nil {
		t.Fatal("run on another tenant's asset stored")
	}

	// The data scope limits the list to the user's assets.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@ci.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		user.String(), tenant.String(), repoB.String()); err != nil {
		t.Fatal(err)
	}
	runs, total, err := repo.ListRuns(ctx, tenant, cirun.RunFilter{DataScope: &shared.DataScope{TenantID: tenant, UserID: user}})
	if err != nil || total != 1 || runs[0].ID != runB.ID {
		t.Fatalf("scoped list: %d %v", total, err)
	}
	if _, total, _ := repo.ListRuns(ctx, tenant, cirun.RunFilter{}); total != 3 {
		t.Fatalf("unrestricted list: %d", total)
	}

	// Replay: one exchange per token id.
	jti := "jti-" + shared.NewID().String()
	if ok, err := repo.ClaimJTI(ctx, "https://issuer.test", jti, now.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, _ := repo.ClaimJTI(ctx, "https://issuer.test", jti, now.Add(time.Hour)); ok {
		t.Fatal("replayed token id accepted")
	}
	if ok, _ := repo.ClaimJTI(ctx, "https://other-issuer.test", jti, now.Add(time.Hour)); !ok {
		t.Fatal("same id from another issuer refused")
	}

	// The findings cap holds across reports.
	fps := make([]string, 0, 3)
	for i := range 3 {
		fps = append(fps, fmt.Sprintf("fp-%d", i))
	}
	if err := repo.RecordRunReport(ctx, tenant, runA.ID, fps); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordRunReport(ctx, tenant, runA.ID, fps[:1]); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetRun(ctx, tenant, runA.ID)
	if got.ReportsCount != 2 || got.FindingsCount != 3 {
		t.Fatalf("counts = %d reports, %d findings", got.ReportsCount, got.FindingsCount)
	}
	if err := repo.RecordRunReport(ctx, other, runA.ID, fps); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant report: %v", err)
	}

	// Overrides: commit prefix, expiry, revocation, tenant.
	o := &cirun.GateOverride{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: repoA, CommitSHA: "abcdef1",
		Reason: "release hotfix", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := repo.CreateOverride(ctx, o); err != nil {
		t.Fatal(err)
	}
	if a, err := repo.ActiveOverride(ctx, tenant, repoA, "abcdef1234567", now); err != nil || a == nil || a.ID != o.ID {
		t.Fatalf("active override: %v %v", a, err)
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, "ffffff1234567", now); a != nil {
		t.Fatal("override matched another commit")
	}
	if a, _ := repo.ActiveOverride(ctx, other, repoA, "abcdef1234567", now); a != nil {
		t.Fatal("override visible to another tenant")
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, "abcdef1234567", now.Add(2*time.Hour)); a != nil {
		t.Fatal("expired override active")
	}
	if err := repo.RevokeOverride(ctx, other, o.ID, shared.NewID(), now); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if err := repo.RevokeOverride(ctx, tenant, o.ID, shared.ID{}, now); err != nil {
		t.Fatal(err)
	}
	if a, _ := repo.ActiveOverride(ctx, tenant, repoA, "abcdef1234567", now); a != nil {
		t.Fatal("revoked override active")
	}
	if list, _ := repo.ListOverrides(ctx, tenant, nil, &shared.DataScope{TenantID: tenant, UserID: user}); len(list) != 0 {
		t.Fatal("override on an asset outside the scope listed")
	}

	// Policies through a business unit; one per scope.
	bu := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'payments')`, bu.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
		shared.NewID().String(), tenant.String(), bu.String(), repoA.String()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.BusinessUnitExists(ctx, other, bu); ok {
		t.Fatal("business unit visible to another tenant")
	}
	p := &cirun.GatePolicy{ID: shared.NewID(), TenantID: tenant, ScopeType: cirun.ScopeBusinessUnit, ScopeID: &bu, Enabled: true,
		Mode: cirun.ModeEnforce, FailOnSeverity: "medium", NewFindingsOnly: true, CreatedAt: now}
	if err := repo.CreateGatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	dup := *p
	dup.ID = shared.NewID()
	if err := repo.CreateGatePolicy(ctx, &dup); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate scope: %v", err)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, tenant, repoA); len(ps) != 1 || ps[0].ID != p.ID {
		t.Fatalf("policies for repo A: %+v", ps)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, tenant, repoB); len(ps) != 0 {
		t.Fatalf("policies for repo B: %+v", ps)
	}
	if ps, _ := repo.GatePoliciesFor(ctx, other, repoA); len(ps) != 0 {
		t.Fatal("another tenant's policy applied")
	}
	if err := repo.DeleteGatePolicy(ctx, other, p.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

func TestCITrustConfigRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Name: "gh", Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Audience: cirun.DefaultAudience(tenant), DefaultBranch: "main", Enabled: true,
		Rules: cirun.Rules{Owners: []string{"acme"}, Refs: []string{"main"}}, CreatedAt: now}
	if err := repo.CreateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	dup := *c
	dup.ID = shared.NewID()
	if err := repo.CreateTrustConfig(ctx, &dup); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, tenant, cirun.GitHubIssuer); len(got) != 1 || got[0].Rules.Owners[0] != "acme" {
		t.Fatalf("enabled: %+v", got)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, other, cirun.GitHubIssuer); len(got) != 0 {
		t.Fatal("another tenant's trust used")
	}
	c.Enabled = false
	if err := repo.UpdateTrustConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.EnabledTrustConfigs(ctx, tenant, cirun.GitHubIssuer); len(got) != 0 {
		t.Fatal("disabled configuration used")
	}
	foreign := *c
	foreign.TenantID = other
	if err := repo.UpdateTrustConfig(ctx, &foreign); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := repo.DeleteTrustConfig(ctx, other, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, err := repo.GetTrustConfig(ctx, other, c.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if err := repo.DeleteTrustConfig(ctx, tenant, c.ID); err != nil {
		t.Fatal(err)
	}
}
