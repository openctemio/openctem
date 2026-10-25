package integration

import (
	"context"
	"testing"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A person's edit of a tracked attribute saves the asset row first and
// records the lock after it. The timeline and the asset history still show
// the change, from the value shown before the edit, with the person.
func TestAssetTimeline_PersonEditIsRecorded(t *testing.T) {
	g := newReconcileRig(t)
	ctx := context.Background()
	const name = "tl-edit.example.com"
	g.importReport(asset.SourceKindImport, "", time.Now().UTC().Add(-time.Hour), withClaims(reconHost(name), "medium", "", ""))
	id := g.assetID(name)
	actor := shared.NewID()
	if _, err := g.r.db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'editor')`,
		actor.String(), actor.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}

	edit := func(in assetapp.UpdateAssetInput) {
		t.Helper()
		in.ActorID = actor.String()
		if _, err := g.assets.UpdateAsset(ctx, id, g.tn.tenant.String(), in); err != nil {
			t.Fatal(err)
		}
	}
	str := func(s string) *string { return &s }

	edit(assetapp.UpdateAssetInput{Criticality: str("high")})
	ev := g.events(name, "criticality")
	if len(ev) != 1 {
		t.Fatalf("first edit: want 1 event, got %+v", ev)
	}
	if e := ev[0]; e.old != "medium" || e.new != "high" || e.kind != "manual" || e.reason != "manual_lock" ||
		e.actor == nil || *e.actor != actor.String() {
		t.Fatalf("first edit event: %+v", e)
	}

	// The same person edits again: the deciding source is unchanged, the
	// value is not, so it is a second entry.
	edit(assetapp.UpdateAssetInput{Criticality: str("critical")})
	ev = g.events(name, "criticality")
	if len(ev) != 2 || ev[1].old != "high" || ev[1].new != "critical" {
		t.Fatalf("second edit: %+v", ev)
	}

	// Saving the same value is no change.
	edit(assetapp.UpdateAssetInput{Criticality: str("critical")})
	if ev = g.events(name, "criticality"); len(ev) != 2 {
		t.Fatalf("unchanged save added an event: %+v", ev)
	}

	// An exposure edit: one timeline event and exactly one history row.
	edit(assetapp.UpdateAssetInput{Exposure: str("public")})
	if ev = g.events(name, "exposure"); len(ev) != 1 || ev[0].new != "public" || ev[0].kind != "manual" {
		t.Fatalf("exposure edit: %+v", ev)
	}
	var crit, expo int
	if err := g.r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE field = 'criticality'), COUNT(*) FILTER (WHERE field = 'exposure')
		  FROM asset_state_history WHERE tenant_id = $1 AND asset_id = $2`,
		g.tn.tenant.String(), id).Scan(&crit, &expo); err != nil {
		t.Fatal(err)
	}
	if crit != 2 || expo != 1 {
		t.Fatalf("history rows: criticality %d (want 2), exposure %d (want 1)", crit, expo)
	}

	// An asset no source ever decided (the stored default): the first edit
	// is an entry too, from the default.
	const bare = "tl-edit-bare.example.com"
	g.importReport(asset.SourceKindImport, "", time.Now().UTC().Add(-time.Hour), withClaims(reconHost(bare), "", "", ""))
	bareID := g.assetID(bare)
	var was string
	if err := g.r.db.QueryRowContext(ctx, `SELECT criticality FROM assets WHERE id = $1`, bareID).Scan(&was); err != nil {
		t.Fatal(err)
	}
	if _, err := g.assets.UpdateAsset(ctx, bareID, g.tn.tenant.String(), assetapp.UpdateAssetInput{
		Criticality: str("critical"), ActorID: actor.String(),
	}); err != nil {
		t.Fatal(err)
	}
	if ev = g.events(bare, "criticality"); len(ev) != 1 || ev[0].old != was || ev[0].new != "critical" {
		t.Fatalf("first edit of a default value (was %q): %+v", was, ev)
	}

	// Another organization's asset of the same name is untouched.
	other := g.r.newTenant("nmap")
	var n int
	if err := g.r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM asset_change_events WHERE tenant_id = $1`, other.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("other organization has %d events", n)
	}
	// An edit under the other organization cannot reach this asset.
	if _, err := g.assets.UpdateAsset(ctx, id, other.tenant.String(), assetapp.UpdateAssetInput{
		Criticality: str("low"), ActorID: actor.String(),
	}); err == nil {
		t.Fatal("an edit under another organization succeeded")
	}
	if ev = g.events(name, "criticality"); len(ev) != 2 {
		t.Fatalf("cross-organization edit changed the timeline: %+v", ev)
	}
}
