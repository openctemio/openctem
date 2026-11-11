package postgres

// The IP addresses tab: the network, port and service filters, the names
// and open ports beside each address (only what the caller may see), the
// group by network, and the plans of the new indexed fields.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetlist"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

func compileAssets(t *testing.T, actor filterspec.Actor, doc map[string]any) *filterspec.Where {
	t.Helper()
	spec, err := filterspec.ParseDocumentValue(doc, assetlist.Fields, filterspec.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	w, err := filterspec.Compile(spec, assetlist.Fields, actor)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return w
}

func leafDoc(field, op string, value any) map[string]any {
	return map[string]any{"filter": map[string]any{"field": field, "op": op, "value": value}}
}

func TestAssetIPTab_FiltersColumnsAndScope(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetRepository(&DB{DB: db})
	ports := NewAssetPortRepository(&DB{DB: db})
	a := seedPorts(ctx, t, db) // 10.9.8.7 exposes 443 and 22; www.example.com resolves to it
	b := seedPorts(ctx, t, db)
	// A second address in the same /24, and a name outside memberA's scope.
	tid := a.tenant.String()
	other := shared.NewID().String()
	hidden := shared.NewID().String()
	for _, row := range [][]string{{other, "10.9.8.200", "ip_address"}, {hidden, "secret.example.com", "subdomain"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1,$2,$3,$4,'active')`,
			row[0], tid, row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1,$2,$3,'resolves_to')`, tid, hidden, a.ip); err != nil {
		t.Fatal(err)
	}
	drainPorts(ctx, t, ports)

	sys := filterspec.SystemActor(a.tenant, "ip tab test")
	ids := func(w *filterspec.Where) string {
		res, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 100})
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(assetIDsSorted(res.Data), ",")
	}
	want := func(v ...string) string {
		out := append([]string(nil), v...)
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := ids(compileAssets(t, sys, leafDoc("network", "in", []any{"10.9.8.0/24"}))); got != want(a.ip, other) {
		t.Fatalf("network=10.9.8.0/24: %s", got)
	}
	if got := ids(compileAssets(t, sys, leafDoc("network", "in", []any{"10.9.8.1"}))); got != want(a.ip, other) {
		t.Fatalf("network of an address: %s", got)
	}
	if got := ids(compileAssets(t, sys, leafDoc("port", "in", []any{22}))); got != want(a.ip, a.port2, a.name, hidden) {
		t.Fatalf("port=22: %s", got)
	}
	if got := ids(compileAssets(t, sys, leafDoc("port", "gte", 400))); got != want(a.ip, a.port, a.name, hidden) {
		t.Fatalf("port>=400: %s", got)
	}
	if got := ids(compileAssets(t, sys, leafDoc("service", "in", []any{"HTTPS"}))); got != want(a.ip, a.port, a.name, hidden) {
		t.Fatalf("service=https: %s", got)
	}

	// Columns as a scoped member who sees the address and www, not secret.
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'u')`, user.String(), user.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a.ip, a.name, a.port} {
		if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1,$2,$3)`,
			user.String(), tid, id); err != nil {
			t.Fatal(err)
		}
	}
	member, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: a.tenant, UserID: user,
		Scope: &shared.DataScope{TenantID: a.tenant, UserID: user}})
	if err != nil {
		t.Fatal(err)
	}
	ctxs, err := repo.IPContexts(ctx, member, []string{a.ip, b.ip})
	if err != nil {
		t.Fatal(err)
	}
	c := ctxs[a.ip]
	if strings.Join(c.Names, ",") != "www.example.com" || c.NamesTotal != 1 {
		t.Fatalf("member names %v total %d (secret.example.com is outside the scope)", c.Names, c.NamesTotal)
	}
	if len(c.Ports) != 1 || c.Ports[0].Port != 443 || c.PortsTotal != 1 {
		t.Fatalf("member ports %+v total %d (port 22 is outside the scope)", c.Ports, c.PortsTotal)
	}
	if _, leaked := ctxs[b.ip]; leaked {
		t.Fatal("another tenant's address got columns")
	}
	full, err := repo.IPContexts(ctx, sys, []string{a.ip})
	if err != nil {
		t.Fatal(err)
	}
	if f := full[a.ip]; f.NamesTotal != 2 || f.PortsTotal != 2 || fmt.Sprint(f.Ports[0].Port) != "22" {
		t.Fatalf("unrestricted columns %+v", f)
	}

	// Group by network: the member sees only the address in scope.
	nets, capped, err := repo.NetworkCounts(ctx, compileAssets(t, member, map[string]any{}))
	if err != nil || capped || len(nets) != 1 || nets[0].Network != "10.9.8.0/24" || nets[0].Count != 1 {
		t.Fatalf("member networks %+v capped %v err %v", nets, capped, err)
	}
	nets, _, err = repo.NetworkCounts(ctx, compileAssets(t, sys, map[string]any{}))
	if err != nil || len(nets) != 1 || nets[0].Count != 2 {
		t.Fatalf("networks %+v err %v", nets, err)
	}
}

// The new indexed fields read their index on a tenant with many assets:
// no sequential scan of assets or asset_ports.
func TestAssetIPTab_ExplainUsesIndexes(t *testing.T) {
	db := openSensorDB(t)
	owner := testdb.OpenMigrator(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	noise := seedTestTenant(ctx, t, db)
	for _, tn := range []shared.ID{tenant, noise} {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status)
			SELECT uuid_generate_v7(), $1, '10.' || (g / 65536) % 256 || '.' || (g / 256) % 256 || '.' || g % 256, 'ip_address', 'active'
			FROM generate_series(1, 8000) g`, tn.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_ports (tenant_id, asset_id, port_asset_id, port, transport, service)
			SELECT tenant_id, id, id, 1000 + (row_number() OVER ()) % 2000, 'tcp', 'svc' FROM assets WHERE tenant_id = $1`, tn.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.ExecContext(ctx, `ANALYZE assets; ANALYZE asset_ports`); err != nil {
		t.Fatal(err)
	}
	sys := filterspec.SystemActor(tenant, "explain test")
	for _, c := range []struct {
		name  string
		doc   map[string]any
		index string
	}{
		{"network", leafDoc("network", "in", []any{"10.0.7.0/24"}), "idx_assets_ip_network"},
		{"ip", leafDoc("ip", "in", []any{"10.0.7.0/24"}), "idx_assets_ip_addr"},
		{"port", leafDoc("port", "in", []any{1443}), "idx_asset_ports_port"},
	} {
		w := compileAssets(t, sys, c.doc)
		//nolint:gosec // G202: compiled from registry constants
		q := "EXPLAIN (FORMAT JSON) SELECT a.id FROM assets a WHERE a.deleted_at IS NULL AND " + w.SQL
		var raw []byte
		if err := db.QueryRowContext(ctx, q, w.Args...).Scan(&raw); err != nil {
			t.Fatalf("%s: explain: %v", c.name, err)
		}
		plan := planText(t, raw)
		if strings.Contains(plan, "Seq Scan on assets") || strings.Contains(plan, "Seq Scan on asset_ports") {
			t.Errorf("%s: sequential scan: %s", c.name, plan)
		}
		if !strings.Contains(plan, c.index) {
			t.Errorf("%s: %s not used: %s", c.name, c.index, plan)
		}
	}
}

// planText flattens an EXPLAIN JSON plan to "node on relation using index"
// lines.
func planText(t *testing.T, raw []byte) string {
	t.Helper()
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("explain json: %v", err)
	}
	var b strings.Builder
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		fmt.Fprintf(&b, "%v on %v using %v; ", n["Node Type"], n["Relation Name"], n["Index Name"])
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					walk(m)
				}
			}
		}
	}
	if root, ok := plans[0]["Plan"].(map[string]any); ok {
		walk(root)
	}
	return b.String()
}
