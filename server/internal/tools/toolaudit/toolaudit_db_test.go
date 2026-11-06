package toolaudit_test

import (
	"context"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/internal/tools/toolaudit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run writes one audit row in each tenant it changed and none in a tenant it
// did not touch; the row carries the actor, the run id and the counts.
func TestRecord_OneRowPerAffectedTenant_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "toolaudit", "../../../migrations")
	ctx := context.Background()
	w := postgres.NewAuditRepository(&postgres.DB{DB: db})

	var tenants [3]shared.ID
	for i := range tenants {
		tenants[i] = shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			tenants[i].String(), "T", "toolaudit-"+tenants[i].String()); err != nil {
			t.Fatal(err)
		}
	}
	run := toolaudit.NewRunID()
	for _, tn := range tenants[:2] {
		if err := toolaudit.Record(ctx, w, toolaudit.Event{
			TenantID: tn, Action: audit.ActionFindingsRefingerprinted, ResourceType: audit.ResourceTypeFinding,
			Actor: "refingerprint", RunID: run, Counts: map[string]int{"rekeyed": 5, "merged": 2},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, tn := range tenants {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'findings.refingerprinted'`, tn.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		want := 1
		if i == 2 {
			want = 0
		}
		if n != want {
			t.Errorf("tenant %d: %d rows, want %d", i, n, want)
		}
	}
	var actor, runID string
	var rekeyed int
	if err := db.QueryRowContext(ctx, `SELECT actor_agent, metadata->>'run_id', (metadata->>'rekeyed')::int FROM audit_logs WHERE tenant_id = $1`, tenants[0].String()).Scan(&actor, &runID, &rekeyed); err != nil {
		t.Fatal(err)
	}
	if actor != "refingerprint" || runID != run || rekeyed != 5 {
		t.Errorf("row = %q %q %d", actor, runID, rekeyed)
	}
	if err := toolaudit.Record(ctx, w, toolaudit.Event{Action: audit.ActionAssetsMerged, ResourceType: audit.ResourceTypeAsset, Actor: "repomerge", RunID: run}); err == nil {
		t.Error("an event without a tenant must be refused")
	}
}
