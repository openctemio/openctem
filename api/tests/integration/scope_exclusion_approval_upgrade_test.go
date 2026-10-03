package integration

// Upgrade test for migration 000267 (scope exclusions need approval).
//
// New exclusions are now created pending and only approved ones are applied.
// The migration must not switch off an exclusion that is in effect today: it
// builds a database at 000266 with exclusions in every state, applies the rest
// of the migrations, and asserts that what was active before is still applied
// (through the real repository read every consumer uses), that nothing else
// became active, that the approve permission went to owner and admin only,
// and that down -> up round-trips.

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const scopeExclusionApprovalVersion = "000267"

func TestScopeExclusionApprovalUpgrade_KeepsLiveExclusions_DB(t *testing.T) {
	db := scratchDatabase(t)
	migs := loadMigrations(t)

	applied := 0
	for _, m := range migs {
		if m.version >= scopeExclusionApprovalVersion {
			break
		}
		execFile(t, db, m.up)
		applied++
	}
	if applied == 0 || applied == len(migs) {
		t.Fatalf("migration %s not found in the migration set", scopeExclusionApprovalVersion)
	}

	tenantID := shared.NewID().String()
	mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Exclusion upgrade', 'excl-upgrade')`, tenantID)
	ids := map[string]string{}
	for _, row := range []struct{ key, pattern, status, approvedBy string }{
		{"active_unapproved", "a.example.com", "active", ""},
		{"active_approved", "b.example.com", "active", "reviewer-1"},
		{"inactive", "c.example.com", "inactive", ""},
		{"expired", "d.example.com", "expired", ""},
	} {
		id := shared.NewID().String()
		ids[row.key] = id
		var approvedBy any
		var approvedAt any
		if row.approvedBy != "" {
			approvedBy, approvedAt = row.approvedBy, "2026-01-02T00:00:00Z"
		}
		mustExec(t, db, `INSERT INTO scope_exclusions
			(id, tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
			VALUES ($1, $2, 'domain', $3, 'pre-upgrade', $4, $5, $6, 'member-1')`,
			id, tenantID, row.pattern, row.status, approvedBy, approvedAt)
	}

	for _, m := range migs[applied:] {
		execFile(t, db, m.up)
	}

	assertLive := func(t *testing.T) {
		t.Helper()
		repo := postgres.NewScopeExclusionRepository(&postgres.DB{DB: db})
		live, err := repo.ListActive(context.Background(), shared.MustIDFromString(tenantID))
		if err != nil {
			t.Fatalf("ListActive: %v", err)
		}
		got := map[string]bool{}
		for _, e := range live {
			got[e.ID().String()] = true
			if !e.IsActive() {
				t.Errorf("ListActive returned %s that is not in effect", e.Pattern())
			}
		}
		if !got[ids["active_unapproved"]] || !got[ids["active_approved"]] || len(got) != 2 {
			t.Fatalf("after upgrade the live exclusions are %v, want exactly the two that were active", got)
		}
	}
	assertLive(t)

	var approvedBy string
	if err := db.QueryRow(`SELECT approved_by FROM scope_exclusions WHERE id = $1`, ids["active_approved"]).Scan(&approvedBy); err != nil {
		t.Fatal(err)
	}
	if approvedBy != "reviewer-1" {
		t.Fatalf("an existing approval was overwritten: approved_by = %q", approvedBy)
	}
	var inactiveApproved sql.NullTime
	if err := db.QueryRow(`SELECT approved_at FROM scope_exclusions WHERE id = $1`, ids["inactive"]).Scan(&inactiveApproved); err != nil {
		t.Fatal(err)
	}
	if inactiveApproved.Valid {
		t.Fatal("an inactive exclusion was marked approved by the migration")
	}

	// The approve permission is seeded and granted to owner and admin only.
	var granted string
	if err := db.QueryRow(`SELECT COALESCE(string_agg(r.slug, ',' ORDER BY r.slug), '')
		FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
		WHERE rp.permission_id = 'attack_surface:scope:exclusions:approve'`).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if granted != "admin,owner" {
		t.Fatalf("approve permission granted to %q, want admin,owner", granted)
	}

	// A row inserted without a status is pending, never live.
	pendingID := shared.NewID().String()
	mustExec(t, db, `INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason)
		VALUES ($1, $2, 'domain', 'e.example.com', 'no status')`, pendingID, tenantID)
	var status string
	if err := db.QueryRow(`SELECT status FROM scope_exclusions WHERE id = $1`, pendingID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("default status = %q, want pending", status)
	}
	assertLive(t)

	// down -> up round-trips and keeps the live set.
	for i := len(migs) - 1; i >= applied; i-- {
		execFile(t, db, migs[i].down)
	}
	for _, m := range migs[applied:] {
		execFile(t, db, m.up)
	}
	assertLive(t)
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
