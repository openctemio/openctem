package integration

// Migration 001181 (RFC-042 §6.3.9): stored asset properties fold their
// synonyms into the canonical key (ip_addresses, nameservers, ...), lose the
// keys only other classes may hold (a port on a domain), keep updated_at,
// and the down migration restores every changed row exactly. Rows of
// another tenant are normalised by the same rule and restored to their own
// values only. Runs as the schema owner in a rolled-back transaction.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001181NormalisesAssetProperties(t *testing.T) {
	appDB := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, appDB)
	tenantB := seedLifecycleTenant(ctx, t, appDB)

	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile("../../migrations/001181_normalise_asset_properties." + name + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up, down := read("up"), read("down")
	for name, sqlText := range map[string]string{"up": up, "down": down} {
		if strings.Contains(strings.ToLower(sqlText), "audit_log") {
			t.Fatalf("%s writes audit rows from SQL", name)
		}
	}

	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	// The database is migrated: take 001181 back first.
	exec(down)

	type row struct {
		tenant     shared.ID
		name, typ  string
		props, out string // out "" = unchanged
	}
	rows := []row{
		{tenantA, "props-domain.example", "domain",
			`{"ip": "202.160.124.20", "ip_addresses": ["202.160.124.20"], "port": "443", "protocol": "tcp", "title": "kept"}`,
			`{"ip_addresses": ["202.160.124.20"], "title": "kept"}`},
		{tenantA, "props-host-1", "host",
			`{"ip_address": {"address": "10.0.0.9", "asn": 1}, "resolved_ips": "10.0.0.10, 2001:DB8::1, junk", "addresses": ["10.0.0.9"]}`,
			`{"ip_address": {"address": "10.0.0.9", "asn": 1}, "ip_addresses": ["10.0.0.9", "10.0.0.10", "2001:db8::1"]}`},
		{tenantA, "203.0.113.5", "ip_address",
			`{"ip": "203.0.113.5", "ips": ["203.0.113.6"]}`,
			`{"ip_addresses": ["203.0.113.6"]}`},
		{tenantA, "props-svc:443", "service",
			`{"port": 443, "banner": "x", "ip": "198.51.100.1", "nameserver": "ns1", "technology": "nginx", "san": "a.example"}`,
			`{"port": 443, "banner": "x", "ip_addresses": ["198.51.100.1"], "nameservers": ["ns1"], "technologies": ["nginx"], "sans": ["a.example"]}`},
		{tenantA, "props-clean.example", "domain", `{"ip_addresses": ["192.0.2.1"], "registrar": "r"}`, ""},
		{tenantA, "props-nothing.example", "domain", `{"ip": "not-an-address"}`, `{}`},
		{tenantB, "props-domain.example", "domain", `{"resolved_ip": "192.0.2.77", "status_code": 200}`,
			`{"ip_addresses": ["192.0.2.77"]}`},
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = shared.NewID().String()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status, properties, updated_at)
			VALUES ($1, $2, $3, $4, 'active', $5::jsonb, '2026-01-01T00:00:00Z')`, ids[i], r.tenant.String(), r.name, r.typ, r.props)
	}
	state := func(id string) (map[string]any, string) {
		t.Helper()
		var raw []byte
		var updated string
		if err := tx.QueryRowContext(ctx, `SELECT properties, updated_at::text FROM assets WHERE id = $1`, id).Scan(&raw, &updated); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m, updated
	}
	asMap := func(s string) map[string]any {
		m := map[string]any{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	exec(up)
	for i, r := range rows {
		got, updated := state(ids[i])
		want := r.out
		if want == "" {
			want = r.props
		}
		if !reflect.DeepEqual(got, asMap(want)) {
			t.Errorf("up: %s %s = %v, want %s", r.typ, r.name, got, want)
		}
		if !strings.HasPrefix(updated, "2026-01-01") {
			t.Errorf("up: %s updated_at changed to %s", r.name, updated)
		}
	}
	var saved int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM asset_properties_pre_001181 WHERE asset_id = ANY($1::uuid[])`,
		"{"+strings.Join(ids, ",")+"}").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved != len(rows)-1 {
		t.Errorf("saved %d rows, want %d (every changed row)", saved, len(rows)-1)
	}
	var leftover int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_proc WHERE proname LIKE 'mig001181%'`).Scan(&leftover); err != nil {
		t.Fatal(err)
	}
	if leftover != 0 {
		t.Errorf("%d helper functions left behind", leftover)
	}

	exec(down)
	for i, r := range rows {
		if got, _ := state(ids[i]); !reflect.DeepEqual(got, asMap(r.props)) {
			t.Errorf("down: %s %s = %v, want %s", r.typ, r.name, got, r.props)
		}
	}
	// And up again, as a deploy after a rollback would.
	exec(up)
	if got, _ := state(ids[0]); !reflect.DeepEqual(got, asMap(rows[0].out)) {
		t.Errorf("up after down: %v", got)
	}
}
