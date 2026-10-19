package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestDryRunRule_MatchesAndCap drives the priority-rule dry run end to end against
// a real database. It seeds a public-exposure asset and four OPEN findings — two
// critical (which a "severity == critical → P0" draft rule matches) and two low
// (which it does not) — then asserts the dry run reports the exact evaluated and
// matched counts, the would-be class on matched findings, the would-be
// distribution, and (with a tight cap) the capped flag. Read-only: it also
// re-reads a finding afterwards to prove nothing was persisted.
//
// Skipped unless DATABASE_URL is set (app_test, never live).
func TestDryRunRule_MatchesAndCap(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	log := logger.NewNop()
	findingRepo := NewFindingRepository(&DB{DB: db})
	assetRepo := NewAssetRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedPublicAsset(ctx, t, db, tenantID)

	// Two critical (match) + two low (no match), all OPEN (status 'new').
	seedFinding(ctx, t, db, tenantID, assetID, "sca", "critical", "new")
	seedFinding(ctx, t, db, tenantID, assetID, "sca", "critical", "new")
	seedFinding(ctx, t, db, tenantID, assetID, "sca", "low", "new")
	probeID := seedFinding(ctx, t, db, tenantID, assetID, "sca", "low", "new")

	classifier := finding.NewPriorityClassificationService(
		findingRepo, assetRepo,
		fakeEPSSRepo{}, fakeKEVRepo{},
		fakeRuleRepo{}, fakeAuditRepo{},
		log,
	)

	// Draft rule: severity == critical → P0.
	draft, err := vulnerability.NewPriorityOverrideRule(
		tenantID, "dry-run", vulnerability.PriorityP0,
		[]vulnerability.RuleCondition{{Field: "severity", Operator: "eq", Value: "critical"}},
		shared.NewID(),
	)
	if err != nil {
		t.Fatalf("NewPriorityOverrideRule: %v", err)
	}

	// Full run (cap high enough for all four).
	res, err := classifier.DryRunRule(ctx, tenantID, draft, 1000, 25)
	if err != nil {
		t.Fatalf("DryRunRule: %v", err)
	}
	if res.Evaluated != 4 {
		t.Fatalf("evaluated = %d, want 4", res.Evaluated)
	}
	if res.Matched != 2 {
		t.Fatalf("matched = %d, want 2 (the two critical findings)", res.Matched)
	}
	if res.Capped {
		t.Fatalf("capped = true, want false (cap 1000 >= 4 findings)")
	}
	if res.Distribution["P0"] != 2 {
		t.Fatalf("would_be_distribution P0 = %d, want 2", res.Distribution["P0"])
	}
	if got := res.Distribution["P0"] + res.Distribution["P1"] + res.Distribution["P2"] + res.Distribution["P3"]; got != 4 {
		t.Fatalf("distribution sums to %d, want 4 (every evaluated finding bucketed)", got)
	}
	if len(res.Sample) != 2 {
		t.Fatalf("sample len = %d, want 2 (matched findings only)", len(res.Sample))
	}
	for _, s := range res.Sample {
		if s.WouldBeClass != "P0" {
			t.Fatalf("sample would_be_class = %q, want P0", s.WouldBeClass)
		}
		if s.Severity != "critical" {
			t.Fatalf("sample severity = %q, want critical", s.Severity)
		}
		if s.CurrentClass == "" || s.FindingID == "" {
			t.Fatalf("sample missing fields: %+v", s)
		}
	}

	// Tight cap: fewer findings evaluated than exist → capped flag set.
	capped, err := classifier.DryRunRule(ctx, tenantID, draft, 2, 25)
	if err != nil {
		t.Fatalf("DryRunRule (capped): %v", err)
	}
	if !capped.Capped {
		t.Fatalf("capped flag = false, want true (cap 2 < 4 open findings)")
	}
	if capped.Cap != 2 {
		t.Fatalf("cap echoed = %d, want 2", capped.Cap)
	}
	if capped.Evaluated > 2 {
		t.Fatalf("evaluated = %d under cap 2, want <= 2", capped.Evaluated)
	}

	// Read-only guarantee: the dry run must not have persisted a class.
	got, err := findingRepo.GetByID(ctx, tenantID, probeID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if pc := got.PriorityClass(); pc != nil {
		t.Fatalf("dry run persisted a priority_class (%q) — it must be read-only", *pc)
	}
}

// TestDryRunRule_FloorKeepsKEVAboveRule: a draft rule that would put every
// critical finding at P3 cannot lower a known-exploited one below P1. The
// dry run reports the floored class and counts it, and reports the tenant's
// open findings next to the evaluated count.
func TestDryRunRule_FloorKeepsKEVAboveRule(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedPublicAsset(ctx, t, db, tenantID)
	kevID := seedFinding(ctx, t, db, tenantID, assetID, "sca", "critical", "new")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET is_in_kev = TRUE WHERE id = $1`, kevID.String()); err != nil {
		t.Fatal(err)
	}
	seedFinding(ctx, t, db, tenantID, assetID, "sca", "critical", "new")

	classifier := finding.NewPriorityClassificationService(
		NewFindingRepository(&DB{DB: db}), NewAssetRepository(&DB{DB: db}),
		fakeEPSSRepo{}, fakeKEVRepo{}, fakeRuleRepo{}, fakeAuditRepo{}, logger.NewNop())
	draft, err := vulnerability.NewPriorityOverrideRule(tenantID, "dry-run", vulnerability.PriorityP3,
		[]vulnerability.RuleCondition{{Field: "severity", Operator: "eq", Value: "critical"}}, shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	res, err := classifier.DryRunRule(ctx, tenantID, draft, 0, 25)
	if err != nil {
		t.Fatalf("DryRunRule: %v", err)
	}
	if res.Matched != 2 || res.Floored != 1 || res.OpenFindings != 2 || res.Capped {
		t.Fatalf("matched=%d floored=%d open=%d capped=%v, want 2/1/2/false", res.Matched, res.Floored, res.OpenFindings, res.Capped)
	}
	if res.Distribution["P1"] != 1 || res.Distribution["P3"] != 1 {
		t.Fatalf("distribution = %v, want one P1 (KEV, floored) and one P3", res.Distribution)
	}
	for _, s := range res.Sample {
		if s.FindingID == kevID.String() && s.WouldBeClass != "P1" {
			t.Fatalf("KEV finding would be %s under a P3 rule, want P1", s.WouldBeClass)
		}
	}
}

// TestPriorityRules_EqualOrderIsDeterministic: two overlapping active rules
// with the same evaluation order always come back in creation order, so the
// same rule wins on every pass. Another tenant's rules are never listed.
func TestPriorityRules_EqualOrderIsDeterministic(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM priority_override_rules WHERE tenant_id = ANY($1::uuid[])`,
			"{"+tenantID.String()+","+other.String()+"}")
	})
	insert := func(tid shared.ID, name, class, at string) {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO priority_override_rules (tenant_id, name, priority_class, conditions, is_active, evaluation_order, created_at)
			VALUES ($1, $2, $3, '[{"field":"severity","operator":"eq","value":"critical"}]', TRUE, 50, $4::timestamptz)`,
			tid.String(), name, class, at); err != nil {
			t.Fatal(err)
		}
	}
	// Inserted newest first, so heap order would tend to return the newer one.
	insert(tenantID, "newer", "P3", "2026-02-01T00:00:00Z")
	insert(tenantID, "older", "P1", "2026-01-01T00:00:00Z")
	insert(other, "foreign", "P0", "2025-01-01T00:00:00Z")

	repo := NewPriorityRuleRepository(&DB{DB: db})
	for i := 0; i < 20; i++ {
		rules, err := repo.ListActiveByTenant(ctx, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 2 || rules[0].Name() != "older" || rules[1].Name() != "newer" {
			names := []string{}
			for _, r := range rules {
				names = append(names, r.Name())
			}
			t.Fatalf("pass %d: rules %v, want [older newer] (no other tenant's rule)", i, names)
		}
	}
}
