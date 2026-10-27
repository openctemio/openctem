package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// The pending-client migration removes metadata-document clients nobody
// approved, and keeps the ones that matter: with a grant, blocked, or asked
// for within the last day.
func TestMCPPendingClientMigrationCleansUnapprovedClients(t *testing.T) {
	const dir = "../../../migrations"
	db := testdb.PrivateDatabase(t, "mcppending", dir)
	v := testdb.MigrationVersion(t, dir, "mcp_oauth_pending_client")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, id := range []string{"junk", "blocked", "recent", "granted"} {
		exec(`INSERT INTO mcp_oauth_clients (client_id, kind, name, redirect_uris)
			VALUES ($1, 'metadata_document', $1, ARRAY['https://x.example/cb'])`, "https://"+id+".example/c.json")
	}
	exec(`INSERT INTO mcp_oauth_clients (client_id, kind, name, redirect_uris)
		VALUES ('dyn', 'dynamic', 'dyn', ARRAY['https://x.example/cb'])`)
	exec(`UPDATE mcp_oauth_clients SET blocked_at = now() WHERE name = 'https://blocked.example/c.json'`)
	exec(`INSERT INTO mcp_oauth_requests (client_ref, redirect_uri, code_challenge, resource, scopes, expires_at)
		SELECT id, 'https://x.example/cb', 'c', 'r', ARRAY['s'], now() FROM mcp_oauth_clients WHERE name = 'https://recent.example/c.json'`)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ('11111111-1111-4111-8111-111111111111', 't', 't-mcp-pending')`)
	exec(`INSERT INTO users (id, email, name) VALUES ('22222222-2222-4222-8222-222222222222', 'mcp-pending@it.test', 'u')`)
	exec(`INSERT INTO mcp_oauth_grants (tenant_id, user_id, client_ref, resource, scopes, expires_at)
		SELECT '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', id, 'r', ARRAY['s'], now() + interval '1 day'
		FROM mcp_oauth_clients WHERE name = 'https://granted.example/c.json'`)

	testdb.Migrate(t, db, dir, v, v, false)

	rows, err := db.Query(`SELECT name FROM mcp_oauth_clients ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"dyn", "https://blocked.example/c.json", "https://granted.example/c.json", "https://recent.example/c.json"}
	if len(got) != len(want) {
		t.Fatalf("clients after cleanup %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("clients after cleanup %v, want %v", got, want)
		}
	}
}
