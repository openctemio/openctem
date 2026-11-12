package integration

// Migration ctem_cycle_charter_object_description (research 458 B2, B7): a
// cycle charter saved as SQL NULL or JSON null becomes {}, after which the
// scope refinement notes write succeeds; the description column exists.
//
// Runs on a private database (the migration changes the table's columns, which
// the app role may not do and which would lock the shared table): all
// migrations, down, seed, up, then up again to prove it is re-runnable.

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestMigrationCTEMCycleCharterObject(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "ctem_cycle_charter_object_description")
	read := func(kind string) string {
		b, err := os.ReadFile(fmt.Sprintf("%s/%d_ctem_cycle_charter_object_description.%s.sql", dir, v, kind))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	db := testdb.PrivateDatabase(t, "migcycle", dir)
	ctx := context.Background()
	tenant := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'cycle migration', $2)`,
		tenant.String(), "test-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	exec(read("down"))
	var sqlNull, jsonNull, object string
	for _, c := range []struct {
		dst     *string
		charter string
	}{{&sqlNull, "NULL"}, {&jsonNull, "'null'::jsonb"}, {&object, `'{"success_criteria":[]}'::jsonb`}} {
		if err := db.QueryRowContext(ctx, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by, charter)
			VALUES ($1, 'c', 'review', gen_random_uuid(), `+c.charter+`) RETURNING id`, tenant.String()).Scan(c.dst); err != nil {
			t.Fatal(err)
		}
	}
	exec(read("up"))
	exec(read("up")) // idempotent: a second run changes nothing and does not fail

	for id, want := range map[string]string{sqlNull: "{}", jsonNull: "{}", object: `{"success_criteria": []}`} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT charter::text FROM ctem_cycles WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("charter of %s = %s, want %s", id, got, want)
		}
	}
	// The notes write of the cycle handler works on the fixed row.
	exec(`UPDATE ctem_cycles
	         SET charter = jsonb_set(CASE WHEN jsonb_typeof(charter) = 'object' THEN charter ELSE '{}'::jsonb END,
	                                 '{scope_refinement_notes}', to_jsonb($2::text), true)
	       WHERE tenant_id = $1 AND id = $3`, tenant.String(), "notes", jsonNull)
	var notes, desc string
	if err := db.QueryRowContext(ctx, `SELECT charter->>'scope_refinement_notes', description FROM ctem_cycles WHERE id = $1`, jsonNull).Scan(&notes, &desc); err != nil || notes != "notes" || desc != "" {
		t.Fatalf("notes %q, description %q (%v)", notes, desc, err)
	}
}
