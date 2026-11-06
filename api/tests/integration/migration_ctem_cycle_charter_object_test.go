package integration

// Migration ctem_cycle_charter_object_description (research 458 B2, B7): a
// cycle charter saved as SQL NULL or JSON null becomes {}, after which the
// scope refinement notes write succeeds; the description column exists. Run inside a transaction that is rolled
// back.

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
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
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
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

	exec(read("down"))
	var sqlNull, jsonNull, object string
	for _, c := range []struct {
		dst     *string
		charter string
	}{{&sqlNull, "NULL"}, {&jsonNull, "'null'::jsonb"}, {&object, `'{"success_criteria":[]}'::jsonb`}} {
		if err := tx.QueryRowContext(ctx, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by, charter)
			VALUES ($1, 'c', 'review', gen_random_uuid(), `+c.charter+`) RETURNING id`, tenant.String()).Scan(c.dst); err != nil {
			t.Fatal(err)
		}
	}
	exec(read("up"))

	for id, want := range map[string]string{sqlNull: "{}", jsonNull: "{}", object: `{"success_criteria": []}`} {
		var got string
		if err := tx.QueryRowContext(ctx, `SELECT charter::text FROM ctem_cycles WHERE id = $1`, id).Scan(&got); err != nil {
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
	if err := tx.QueryRowContext(ctx, `SELECT charter->>'scope_refinement_notes', description FROM ctem_cycles WHERE id = $1`, jsonNull).Scan(&notes, &desc); err != nil || notes != "notes" || desc != "" {
		t.Fatalf("notes %q, description %q (%v)", notes, desc, err)
	}
}
