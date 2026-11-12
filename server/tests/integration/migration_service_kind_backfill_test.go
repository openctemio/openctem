package integration

// Migration service_kind_backfill: every stored service gets the kind,
// category and source the Go classifier (asset.ClassifyService) gives its
// own properties; a measured name outside the table gets none; a row with
// a kind keeps it; open ports whose protocol held the transport get it
// moved to transport; other types are untouched; each row is classified
// from its own properties only (a row of another tenant changes nothing);
// down removes the keys again.
//
// Runs on a private database: everything up, this migration down, seed, up.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

func TestMigrationServiceKindBackfill(t *testing.T) {
	const dir = "../../migrations"
	ctx := context.Background()
	db := testdb.PrivateDatabase(t, "migservicekind", dir)
	v := testdb.MigrationVersion(t, dir, "service_kind_backfill")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA = "a1111111-1111-4111-8111-111111111441"
		tenantB = "b2222222-2222-4222-8222-222222222441"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-svckind-a'), ($2, 'b', 'mig-svckind-b')`, tenantA, tenantB)

	type row struct {
		id, tenant, name, typ, sub, tool string
		props                            map[string]any
	}
	rows := []row{
		{"01000000-0000-4000-8000-000000000441", tenantA, "198.51.100.1:3389:tcp", "service", "open_port", "naabu", map[string]any{"port": 3389, "protocol": "tcp"}},
		{"01000000-0000-4000-8000-000000000442", tenantA, "198.51.100.1:443:tcp", "service", "open_port", "naabu", map[string]any{"port": 443, "transport": "tcp"}},
		{"01000000-0000-4000-8000-000000000443", tenantA, "https://a.example.com", "service", "http", "httpx", map[string]any{"port": 22, "protocol": "https", "scheme": "https"}},
		{"01000000-0000-4000-8000-000000000444", tenantA, "https://b.example.com", "service", "http", "nuclei", map[string]any{}},
		{"01000000-0000-4000-8000-000000000445", tenantA, "198.51.100.1:5432:tcp", "service", "open_port", "nessus", map[string]any{"port": 5432, "protocol": "postgres"}},
		{"01000000-0000-4000-8000-000000000446", tenantA, "198.51.100.1:443:tcp:x", "service", "open_port", "nessus", map[string]any{"port": 443, "protocol": "acme-proto"}},
		{"01000000-0000-4000-8000-000000000447", tenantA, "198.51.100.1:22:tcp", "service", "open_port", "import", map[string]any{"port": 22, "protocol": "ssh?"}},
		{"01000000-0000-4000-8000-000000000448", tenantA, "198.51.100.1:161:udp", "service", "open_port", "naabu", map[string]any{"port": 161, "protocol": "udp"}},
		{"01000000-0000-4000-8000-000000000449", tenantA, "198.51.100.1:5000:tcp", "service", "open_port", "naabu", map[string]any{"port": 5000}},
		{"01000000-0000-4000-8000-00000000044a", tenantA, "198.51.100.1:993:tcp", "service", "open_port", "nessus", map[string]any{"port": 993, "protocol": "SSL/IMAP"}},
		{"02000000-0000-4000-8000-000000000441", tenantB, "203.0.113.9:6379:tcp", "service", "open_port", "naabu", map[string]any{"port": 6379}},
	}
	insert := func(r row) {
		raw, _ := json.Marshal(r.props)
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status, discovery_tool, properties)
			VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)`, r.id, r.tenant, r.name, r.typ, r.sub, r.tool, string(raw))
	}
	for _, r := range rows {
		insert(r)
	}
	// Already classified: left alone.
	kept := row{"01000000-0000-4000-8000-00000000044b", tenantA, "198.51.100.1:80:tcp", "service", "open_port", "svcdetect",
		map[string]any{"port": 80, "service_kind": "ssh", "service_category": "remote_access", "kind_source": "fingerprint"}}
	insert(kept)
	// Not a service: untouched.
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status, properties) VALUES
		('01000000-0000-4000-8000-00000000044c', $1, 'host.example.com', 'host', 'active', '{"port": 3389, "protocol": "rdp"}')`, tenantA)

	testdb.Migrate(t, db, dir, v, v, false)

	props := func(id string) map[string]any {
		t.Helper()
		var raw []byte
		if err := db.QueryRowContext(ctx, `SELECT properties FROM assets WHERE id = $1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	// The backfill agrees with the Go classifier, row by row.
	for _, r := range rows {
		in := map[string]any{}
		for k, val := range r.props {
			in[k] = val
		}
		if p, ok := in["protocol"].(string); ok && (p == "tcp" || p == "udp") {
			in["transport"] = p
			delete(in, "protocol")
		}
		evidence := asset.KindSourceReported
		if r.sub == "http" && r.tool == "httpx" {
			evidence = asset.KindSourceHTTPProbe
		}
		want, ok := asset.ClassifyService(r.sub, in, nil, evidence)
		got := props(r.id)
		if !ok {
			if _, has := got["service_kind"]; has {
				t.Errorf("%s: kind %v, want none", r.name, got["service_kind"])
			}
			continue
		}
		if got["service_kind"] != want.Kind || got["service_category"] != want.Category || got["kind_source"] != string(want.Source) {
			t.Errorf("%s: got %v/%v/%v, want %+v", r.name, got["service_kind"], got["service_category"], got["kind_source"], want)
		}
	}
	// Spot checks of the expected outcome.
	if p := props(rows[0].id); p["service_kind"] != "rdp" || p["kind_source"] != "port_guess" || p["transport"] != "tcp" || p["protocol"] != nil {
		t.Errorf("rdp port: %v", p)
	}
	if p := props(rows[5].id); p["service_kind"] != nil {
		t.Errorf("unknown measured name got a kind: %v", p)
	}
	if p := props(kept.id); p["service_kind"] != "ssh" || p["kind_source"] != "fingerprint" {
		t.Errorf("classified row changed: %v", p)
	}
	if p := props("01000000-0000-4000-8000-00000000044c"); p["service_kind"] != nil {
		t.Errorf("host classified: %v", p)
	}
	if p := props(rows[10].id); p["service_kind"] != "redis" || p["kind_source"] != "port_guess" {
		t.Errorf("tenant b row: %v", p)
	}

	// Down removes the keys and restores protocol from transport.
	testdb.Migrate(t, db, dir, v, v, true)
	if p := props(rows[0].id); p["service_kind"] != nil || p["protocol"] != "tcp" {
		t.Errorf("down: %v", p)
	}
	if p := props(kept.id); p["service_kind"] != nil {
		t.Errorf("down kept kind: %v", p)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE properties ? 'service_kind'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("down left %d kinds", n)
	}
	// Up again is the same.
	testdb.Migrate(t, db, dir, v, v, false)
	if p := props(rows[0].id); p["service_kind"] != "rdp" {
		t.Errorf("up again: %v", p)
	}
}
