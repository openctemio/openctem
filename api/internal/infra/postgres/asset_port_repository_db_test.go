package postgres

// Open ports of assets: the worker derives rows for the open_port service,
// the address that exposes it and the names that resolve to it; it follows
// edge and port changes; another tenant's rows are never written or read.

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type portSeed struct {
	tenant                           shared.ID
	ip, port, port2, name, unrelated string
}

func seedPorts(ctx context.Context, t *testing.T, db *sql.DB) portSeed {
	t.Helper()
	s := portSeed{tenant: seedTestTenant(ctx, t, db)}
	tid := s.tenant.String()
	mk := func(name, typ, sub, props string) string {
		id := shared.NewID().String()
		var subType any
		if sub != "" {
			subType = sub
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status, properties)
			VALUES ($1, $2, $3, $4, $5, 'active', $6::jsonb)`, id, tid, name, typ, subType, props); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	edge := func(src, dst, typ string) {
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
			VALUES ($1, $2, $3, $4)`, tid, src, dst, typ); err != nil {
			t.Fatalf("seed edge: %v", err)
		}
	}
	s.ip = mk("10.9.8.7", "ip_address", "", `{}`)
	s.port = mk("10.9.8.7:443", "service", "open_port", `{"port": 443, "transport": "TCP", "service": "HTTPS"}`)
	s.port2 = mk("10.9.8.7:22", "service", "open_port", `{"port": "22", "protocol": "tcp", "name": "ssh"}`)
	s.name = mk("www.example.com", "subdomain", "", `{}`)
	s.unrelated = mk("other.example.com", "subdomain", "", `{}`)
	edge(s.ip, s.port, "exposes")
	edge(s.ip, s.port2, "exposes")
	edge(s.name, s.ip, "resolves_to")
	return s
}

func drainPorts(ctx context.Context, t *testing.T, repo *AssetPortRepository) {
	t.Helper()
	for range 20 {
		res, err := repo.ProcessQueue(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		if res.Claimed == 0 {
			return
		}
	}
	t.Fatal("the queue did not drain")
}

func portRows(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, asset string) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT port || '/' || transport || '/' || service FROM asset_ports
		WHERE tenant_id = $1 AND asset_id = $2`, tenant.String(), asset)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestAssetPorts_DerivedAndFollowChanges(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAssetPortRepository(&DB{DB: db})
	a := seedPorts(ctx, t, db)
	b := seedPorts(ctx, t, db)
	drainPorts(ctx, t, repo)

	if got := portRows(ctx, t, db, a.tenant, a.ip); got != "22/tcp/ssh,443/tcp/https" {
		t.Fatalf("address rows = %q", got)
	}
	if got := portRows(ctx, t, db, a.tenant, a.name); got != "22/tcp/ssh,443/tcp/https" {
		t.Fatalf("name rows = %q", got)
	}
	if got := portRows(ctx, t, db, a.tenant, a.port); got != "443/tcp/https" {
		t.Fatalf("port rows = %q", got)
	}
	if got := portRows(ctx, t, db, a.tenant, a.unrelated); got != "" {
		t.Fatalf("unrelated rows = %q", got)
	}
	// Tenant isolation: tenant a's ids read nothing as tenant b, and no row
	// ever pairs an asset with another tenant's port.
	if got := portRows(ctx, t, db, b.tenant, a.ip); got != "" {
		t.Fatalf("tenant b reads tenant a's rows: %q", got)
	}
	var cross int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM asset_ports ap JOIN assets p ON p.id = ap.port_asset_id
		WHERE p.tenant_id <> ap.tenant_id`).Scan(&cross); err != nil || cross != 0 {
		t.Fatalf("cross-tenant rows: %d %v", cross, err)
	}

	// The name stops resolving: its rows go; the address keeps its own.
	if _, err := db.ExecContext(ctx, `DELETE FROM asset_relationships WHERE tenant_id = $1 AND source_asset_id = $2`,
		a.tenant.String(), a.name); err != nil {
		t.Fatal(err)
	}
	// A port closes (inactive): every row naming it goes.
	if _, err := db.ExecContext(ctx, `UPDATE assets SET status = 'inactive' WHERE id = $1`, a.port2); err != nil {
		t.Fatal(err)
	}
	drainPorts(ctx, t, repo)
	if got := portRows(ctx, t, db, a.tenant, a.name); got != "" {
		t.Fatalf("name rows after the edge went = %q", got)
	}
	if got := portRows(ctx, t, db, a.tenant, a.ip); got != "443/tcp/https" {
		t.Fatalf("address rows after the port closed = %q", got)
	}
	// Tenant b is untouched by tenant a's changes.
	if got := portRows(ctx, t, db, b.tenant, b.name); got != "22/tcp/ssh,443/tcp/https" {
		t.Fatalf("tenant b changed: %q", got)
	}
}
