package postgres

// The one-off backfill of asset_ip_addresses (asset_ip_addresses_backfill,
// run by migration asset_ip_addresses_backfill): assets written before the
// triggers existed get their addresses, a deleted asset gets none, rows the
// triggers keep are not touched, and a second run changes nothing.

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestAssetIPAddressesBackfill_DB(t *testing.T) {
	db := openSensorDB(t)
	admin := testdb.OpenAdmin(t)
	owner := testdb.OpenMigrator(t) // the migration runs the backfill as the schema owner
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)

	// Rows planted with triggers off stand for assets that existed before
	// the triggers: no address rows.
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Skipf("cannot plant rows with triggers off: %v", err)
	}
	old := map[string]string{}
	for _, r := range [][3]string{
		{"10.66.0.1", "ip_address", `{}`},
		{"web.example.com", "host", `{"ip_addresses": ["10.66.0.2", "10.66.0.3"], "private_ip": "10.66.0.4"}`},
		{"www.example.com", "domain", `{"ip_addresses": ["10.66.0.5"]}`},
		{"gone.example.com", "host", `{"ip_addresses": ["10.66.0.6"]}`},
	} {
		id := shared.NewID().String()
		old[r[0]] = id
		if _, err := conn.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1, $2, $3, $4, $5::jsonb)`,
			id, tenant.String(), r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, old["gone.example.com"]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
	// An asset written after the triggers: its rows are already there.
	fresh := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1, $2, 'new.example.com', 'host', '{"public_ip": "198.51.100.66"}')`,
		fresh, tenant.String()); err != nil {
		t.Fatal(err)
	}

	addresses := func() map[string][]string {
		t.Helper()
		rows, err := db.QueryContext(ctx, `SELECT a.name, host(x.addr) FROM asset_ip_addresses x JOIN assets a ON a.id = x.asset_id
			WHERE x.tenant_id = $1 ORDER BY 1, 2`, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][]string{}
		for rows.Next() {
			var n, addr string
			if err := rows.Scan(&n, &addr); err != nil {
				t.Fatal(err)
			}
			out[n] = append(out[n], addr)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := addresses(); len(got) != 1 || !slices.Equal(got["new.example.com"], []string{"198.51.100.66"}) {
		t.Fatalf("before the backfill: %v, want only new.example.com", got)
	}

	want := map[string][]string{
		"10.66.0.1":       {"10.66.0.1"},
		"web.example.com": {"10.66.0.2", "10.66.0.3", "10.66.0.4"},
		"new.example.com": {"198.51.100.66"},
	}
	// The CALL is the only statement, as in the migration file, so the
	// procedure may commit between batches; a batch of 2 assets makes it
	// take several. On the first run a writer holds web.example.com (a
	// write that does not touch its addresses, so no trigger copies them):
	// its batch skips it, and the final pass copies it after the writer.
	for run := 1; run <= 2; run++ {
		var writer *sql.Tx
		if run == 1 {
			if writer, err = db.BeginTx(ctx, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.ExecContext(ctx, `UPDATE assets SET last_seen = now() WHERE id = $1`, old["web.example.com"]); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() {
			_, err := owner.ExecContext(ctx, `CALL public.asset_ip_addresses_backfill(2)`)
			done <- err
		}()
		if writer != nil {
			time.Sleep(500 * time.Millisecond) // the batches run past the held row
			if err := writer.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		if err := <-done; err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		got := addresses()
		if len(got) != len(want) {
			t.Fatalf("run %d: %v, want %v", run, got, want)
		}
		for n, addrs := range want {
			if !slices.Equal(got[n], addrs) {
				t.Errorf("run %d: %s = %v, want %v", run, n, got[n], addrs)
			}
		}
	}

	if _, err := owner.ExecContext(ctx, `CALL public.asset_ip_addresses_backfill(0)`); err == nil {
		t.Error("batch_size 0 accepted, want an error")
	}
}
