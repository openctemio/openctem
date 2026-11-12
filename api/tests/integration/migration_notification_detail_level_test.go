package integration

// Migration notification_detail_level: existing channels keep what they
// send (details on -> full, off -> minimal), a new channel defaults to
// standard, an unknown level is refused; the down migration restores
// include_details from the level.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationNotificationDetailLevel(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "notification_detail_level")
	db := testdb.PrivateDatabase(t, "mignotlvl", dir)
	ctx := context.Background()
	const (
		tenant             = "a2222222-1111-4111-8111-111111111111"
		chOn, chOff, chNew = "d1111111-1111-4111-8111-111111111111", "d2222222-2222-4222-8222-222222222222", "d3333333-3333-4333-8333-333333333333"
	)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	level := func(id string) string {
		t.Helper()
		var l string
		if err := db.QueryRowContext(ctx, `SELECT detail_level FROM integration_notification_extensions WHERE integration_id = $1`, id).Scan(&l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-notlvl')`, tenant)
	for i, id := range []string{chOn, chOff, chNew} {
		exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status, auth_type)
			VALUES ($1, $2, $3, 'notification', 'telegram', 'connected', 'token')`, id, tenant, "ch"+string(rune('a'+i)))
	}

	testdb.Migrate(t, db, dir, v, v, true)
	exec(`INSERT INTO integration_notification_extensions (integration_id, include_details) VALUES ($1, true), ($2, false)`, chOn, chOff)
	testdb.Migrate(t, db, dir, v, v, false)

	if got := level(chOn); got != "full" {
		t.Errorf("details on became %q, want full", got)
	}
	if got := level(chOff); got != "minimal" {
		t.Errorf("details off became %q, want minimal", got)
	}
	exec(`INSERT INTO integration_notification_extensions (integration_id) VALUES ($1)`, chNew)
	if got := level(chNew); got != "standard" {
		t.Errorf("new channel default %q, want standard", got)
	}
	if _, err := db.ExecContext(ctx, `UPDATE integration_notification_extensions SET detail_level = 'everything' WHERE integration_id = $1`, chNew); err == nil {
		t.Error("unknown level accepted")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var on, off, std bool
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT include_details FROM integration_notification_extensions WHERE integration_id = $1),
		(SELECT include_details FROM integration_notification_extensions WHERE integration_id = $2),
		(SELECT include_details FROM integration_notification_extensions WHERE integration_id = $3)`, chOn, chOff, chNew).Scan(&on, &off, &std); err != nil {
		t.Fatal(err)
	}
	if !on || off || !std {
		t.Errorf("down: include_details on=%v off=%v standard=%v, want true false true", on, off, std)
	}
}
