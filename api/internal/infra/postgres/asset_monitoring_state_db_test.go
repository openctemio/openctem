package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The SQL monitoring state (the list filter and the row label) agrees with
// asset.MonitoringStateOf on every precedence case, in both unclassified
// modes, and reads only the asset's own tenant: another tenant's exclusion
// that would match the same name changes nothing.
func TestAssetMonitoringState_SQLMatchesDomain(t *testing.T) {
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
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	tid := tenant.String()
	exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.ms-in.example', 'active')`, tid)
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at, kind)
		VALUES ($1, 'domain', 'dns.ms-in.example', 'fragile', 'active', now(), 'do_not_scan'),
		       ($1, 'domain', 'old.ms-in.example', 'gone', 'active', now(), 'retired'),
		       ($1, 'domain', 'sold.ms-in.example', 'sold', 'active', now(), 'not_ours'),
		       ($1, 'domain', 'pending.ms-in.example', 'not yet', 'pending', NULL, 'not_ours')`, tid)
	// Another tenant excludes a name this tenant also has: no effect here.
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at, kind)
		VALUES ($1, 'domain', 'api.ms-in.example', 'theirs', 'active', now(), 'not_ours')`, other.String())

	type seed struct {
		name, status, attState string
		confidence             int
		in                     asset.MonitoringInputs
	}
	seeds := []seed{
		{"api.ms-in.example", "active", "", 0, asset.MonitoringInputs{Status: "active", ScopeStatus: "in_scope"}},
		{"free.ms-out.example", "active", "confirmed", 100, asset.MonitoringInputs{AttributionState: "confirmed", Confidence: 100, Status: "active", ScopeStatus: "not_covered"}},
		{"ref.ms-in.example", "active", "monitor_only", 100, asset.MonitoringInputs{AttributionState: "monitor_only", Confidence: 100, Status: "active", ScopeStatus: "in_scope"}},
		{"cand.ms-in.example", "active", "candidate", 40, asset.MonitoringInputs{AttributionState: "candidate", Confidence: 40, Status: "active", ScopeStatus: "in_scope"}},
		{"low.ms-in.example", "active", "discovered", 60, asset.MonitoringInputs{AttributionState: "discovered", Confidence: 60, Status: "active", ScopeStatus: "in_scope"}},
		{"high.ms-in.example", "active", "discovered", 95, asset.MonitoringInputs{AttributionState: "discovered", Confidence: 95, Status: "active", ScopeStatus: "in_scope"}},
		{"rev.ms-in.example", "active", "needs_review", 50, asset.MonitoringInputs{AttributionState: "needs_review", Confidence: 50, Status: "active", ScopeStatus: "in_scope"}},
		{"gone.ms-in.example", "inactive", "needs_review", 50, asset.MonitoringInputs{AttributionState: "needs_review", Confidence: 50, Status: "inactive", ScopeStatus: "in_scope"}},
		{"dns.ms-in.example", "inactive", "", 0, asset.MonitoringInputs{Status: "inactive", ExclusionKinds: []string{"do_not_scan"}}},
		{"old.ms-in.example", "active", "", 0, asset.MonitoringInputs{Status: "active", ExclusionKinds: []string{"retired"}}},
		{"sold.ms-in.example", "active", "", 0, asset.MonitoringInputs{Status: "active", ExclusionKinds: []string{"not_ours"}}},
		{"rej.ms-in.example", "active", "rejected", 0, asset.MonitoringInputs{AttributionState: "rejected", Status: "active", ScopeStatus: "in_scope"}},
		{"pending.ms-in.example", "active", "", 0, asset.MonitoringInputs{Status: "active", ScopeStatus: "in_scope"}},
	}
	repo := NewAssetRepository(&DB{DB: db})
	ids := make([]string, 0, len(seeds))
	byID := map[string]seed{}
	for _, s := range seeds {
		id := shared.NewID().String()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, status)
			VALUES ($1, $2, $3, 'subdomain', 'public', 'medium', $4)`, id, tid, s.name, s.status)
		if s.attState != "" {
			exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, $4)`,
				id, tid, s.attState, s.confidence)
		}
		ids = append(ids, id)
		byID[id] = s
	}
	for _, scanned := range []bool{false, true} {
		got, err := repo.MonitoringStates(ctx, tenant, ids, scanned)
		if err != nil {
			t.Fatal(err)
		}
		for id, s := range byID {
			in := s.in
			in.UnclassifiedScanned = scanned
			if want := string(asset.MonitoringStateOf(in)); got[id] != want {
				t.Errorf("%s (scanned=%v): SQL %q, domain %q", s.name, scanned, got[id], want)
			}
		}
		// The list filter selects exactly the rows the label names.
		f := asset.Filter{MonitoringStates: []string{string(asset.MonitoringUnvalidated)}, UnclassifiedScanned: scanned}
		f.TenantID = &tid
		res, err := repo.List(ctx, f, asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Data) != 2 {
			names := make([]string, 0, len(res.Data))
			for _, a := range res.Data {
				names = append(names, a.Name())
			}
			t.Errorf("filter unvalidated (scanned=%v) = %v, want cand and low", scanned, names)
		}
	}
	// Another tenant's ids are never answered.
	got, err := repo.MonitoringStates(ctx, other, ids, true)
	if err != nil || len(got) != 0 {
		t.Fatalf("another tenant read %d states (%v)", len(got), err)
	}
}
