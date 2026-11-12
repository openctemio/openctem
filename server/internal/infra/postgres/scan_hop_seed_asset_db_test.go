package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A seed target names the tenant's own inventory asset: a name, an address
// and an open port ("host:port" is stored as "host:port:tcp"). A wildcard, a
// target nothing names, another tenant's asset of the same name and a
// deleted asset link nothing.
func TestScanHops_SeedTargetsNameTheirAsset(t *testing.T) {
	db := openHopDB(t)
	repo := NewScanHopRepository(&DB{DB: db})
	ctx := context.Background()
	a, b := newHopTenant(t, db, 0), newHopTenant(t, db, 0)

	asset := func(tn *hopTenant, name, typ string) shared.ID {
		id := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, $4)`, id, tn.tenant, name, typ)
		return id
	}
	name := asset(a, "app.acme.test", "subdomain")
	addr := asset(a, "203.0.113.7", "ip_address")
	port := asset(a, "203.0.113.7:8443:tcp", "service")
	gone := asset(a, "old.acme.test", "subdomain")
	hopExec(t, db, `UPDATE assets SET deleted_at = now() WHERE id = $1`, gone)
	other := asset(b, "only-b.acme.test", "subdomain")
	_ = asset(b, "app.acme.test", "subdomain") // same name, other tenant

	seed := func(key string) scanrun.RunTarget {
		return scanrun.RunTarget{TargetKey: key, Origin: scanrun.TargetOriginSeed, Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonSeed}
	}
	plan := &scanrun.StagePlan{TenantID: a.tenant, RunID: a.run, StageKey: "ports", Stage: "scan.ports", Tool: "naabu", Planned: 6}
	rows := []scanrun.RunTarget{seed("app.acme.test"), seed("203.0.113.7"), seed("203.0.113.7:8443"),
		seed("*.acme.test"), seed("old.acme.test"), seed("only-b.acme.test")}
	if ok, err := repo.SaveStagePlan(ctx, plan, rows); err != nil || !ok {
		t.Fatalf("save: %v %v", ok, err)
	}

	got := map[string]string{}
	rs, err := db.QueryContext(ctx, `SELECT target_key, COALESCE(asset_id::text, '') FROM scan_run_targets WHERE run_id = $1`, a.run.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	for rs.Next() {
		var k, v string
		if err := rs.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		got[k] = v
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"app.acme.test": name.String(), "203.0.113.7": addr.String(), "203.0.113.7:8443": port.String(),
		"*.acme.test": "", "old.acme.test": "", "only-b.acme.test": "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("seed %q asset = %q, want %q", k, got[k], w)
		}
	}
	if got["only-b.acme.test"] == other.String() {
		t.Error("a seed was linked to another tenant's asset")
	}
}
