package integration

// Every timeline entry of a status change records the lifecycle version it
// was decided under, whatever writer inserted it: a person's move (an
// activity row the service writes) and a platform move (the transition
// timeline trigger). Entries that are not status changes record none. The
// SQL version is the Go constant.

import (
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestFindingActivityLifecycleVersion(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database unreachable: %v", err)
	}

	var v string
	if err := db.QueryRow(`SELECT finding_lifecycle_version()`).Scan(&v); err != nil || v != vulnerability.PlatformLifecycleVersion {
		t.Fatalf("finding_lifecycle_version() = %q (%v), want %q", v, err, vulnerability.PlatformLifecycleVersion)
	}

	var tenant, asset, finding string
	if err := db.QueryRow(`INSERT INTO tenants (name, slug) VALUES ('lv', 'lv-' || gen_random_uuid()) RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant) })
	if err := db.QueryRow(`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, 'lv.example.com', 'domain') RETURNING id::text`, tenant).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, 'dast', 't', 'm', 'high', 'lv-' || gen_random_uuid(), 'new') RETURNING id::text`, tenant, asset).Scan(&finding); err != nil {
		t.Fatal(err)
	}

	// A person's move: the service inserts the entry itself.
	if _, err := db.Exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source)
		VALUES ($1, $2, 'status_changed', 'user', '{"old_status": "new", "new_status": "confirmed"}', 'api')`, tenant, finding); err != nil {
		t.Fatal(err)
	}
	// A comment is no status change.
	if _, err := db.Exec(`INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source)
		VALUES ($1, $2, 'comment_added', 'user', '{"comment_id": "x"}', 'api')`, tenant, finding); err != nil {
		t.Fatal(err)
	}
	// A platform move: the timeline trigger writes the entry.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('openctem.transition', '{"source": "test", "reason": "platform"}', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, finding); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`SELECT activity_type, source, COALESCE(lifecycle_version, ''), COALESCE(changes->>'lifecycle_version', '')
		FROM finding_activities WHERE finding_id = $1 ORDER BY created_at`, finding)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var typ, source, col, inChanges string
		if err := rows.Scan(&typ, &source, &col, &inChanges); err != nil {
			t.Fatal(err)
		}
		seen++
		want := vulnerability.PlatformLifecycleVersion
		if typ == "comment_added" {
			want = ""
		}
		if col != want || inChanges != want {
			t.Errorf("%s/%s: lifecycle_version %q, changes %q; want %q", typ, source, col, inChanges, want)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 3 {
		t.Fatalf("entries = %d, want 3 (person move, comment, platform move)", seen)
	}
}
