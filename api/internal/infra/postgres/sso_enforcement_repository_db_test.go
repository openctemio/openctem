package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// seedSSOOrg creates an organization with an owner and an admin, each a real
// user, and returns their ids.
func seedSSOOrg(t *testing.T, ctx context.Context, db *sql.DB, label string) (tenantID, owner, admin shared.ID) {
	t.Helper()
	tenantID, owner, admin = shared.NewID(), shared.NewID(), shared.NewID()
	slug := label + "-" + tenantID.String()[28:]
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, tenantID.String(), label, slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1, $2)`, owner.String(), admin.String())
	})
	for i, u := range []shared.ID{owner, admin} {
		email := label + "-" + u.String()[28:] + "@example.test"
		if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u.String(), email, "u"); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		role := []string{"owner", "admin"}[i]
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u.String(), tenantID.String(), role); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}
	return tenantID, owner, admin
}

func TestSSOEnforcementRepository(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	ctx := context.Background()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	repo := NewSSOEnforcementRepository(&DB{DB: sqlDB})

	tenantA, ownerA, adminA := seedSSOOrg(t, ctx, sqlDB, "ssoa")
	tenantB, ownerB, _ := seedSSOOrg(t, ctx, sqlDB, "ssob")

	t.Run("an administrator SSO sign-in is per organization and owner/admin only", func(t *testing.T) {
		if ok, err := repo.HasAdminSSOSignIn(ctx, tenantA); err != nil || ok {
			t.Fatalf("before any sign-in: %v %v", ok, err)
		}
		// A sign-in recorded for org B (or for a plain member) never counts for A.
		if err := repo.RecordSSOSignIn(ctx, tenantB, ownerB); err != nil {
			t.Fatal(err)
		}
		if ok, _ := repo.HasAdminSSOSignIn(ctx, tenantA); ok {
			t.Fatal("another organization's sign-in counted")
		}
		member := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'm')`, member.String(), "m-"+member.String()[28:]+"@example.test"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, member.String()) })
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, member.String(), tenantA.String()); err != nil {
			t.Fatal(err)
		}
		if err := repo.RecordSSOSignIn(ctx, tenantA, member); err != nil {
			t.Fatal(err)
		}
		if ok, _ := repo.HasAdminSSOSignIn(ctx, tenantA); ok {
			t.Fatal("a plain member's sign-in counted")
		}
		if err := repo.RecordSSOSignIn(ctx, tenantA, adminA); err != nil {
			t.Fatal(err)
		}
		if ok, err := repo.HasAdminSSOSignIn(ctx, tenantA); err != nil || !ok {
			t.Fatalf("admin sign-in not seen: %v %v", ok, err)
		}
	})

	t.Run("owner second factor is the owner's own, in this organization", func(t *testing.T) {
		if ok, _ := repo.HasOwnerWithSecondFactor(ctx, tenantA); ok {
			t.Fatal("no factor yet")
		}
		// An admin's factor is not an owner's.
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO user_mfa (user_id, enabled) VALUES ($1, true)`, adminA.String()); err != nil {
			t.Fatal(err)
		}
		if ok, _ := repo.HasOwnerWithSecondFactor(ctx, tenantA); ok {
			t.Fatal("an admin's factor counted")
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO user_mfa (user_id, enabled) VALUES ($1, true)`, ownerB.String()); err != nil {
			t.Fatal(err)
		}
		if ok, _ := repo.HasOwnerWithSecondFactor(ctx, tenantA); ok {
			t.Fatal("another organization's owner counted")
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO user_mfa (user_id, enabled) VALUES ($1, true)`, ownerA.String()); err != nil {
			t.Fatal(err)
		}
		if ok, err := repo.HasOwnerWithSecondFactor(ctx, tenantA); err != nil || !ok {
			t.Fatalf("owner factor not seen: %v %v", ok, err)
		}
	})

	t.Run("credentials are counted and revoked for one organization only", func(t *testing.T) {
		insertKey := func(tid, uid shared.ID, suffix string) {
			if _, err := sqlDB.ExecContext(ctx, `
				INSERT INTO api_keys (tenant_id, user_id, name, key_hash, key_prefix, status)
				VALUES ($1, $2, $4, $3, 'rda_xxxxxx', 'active')`, tid.String(), uid.String(), "hash-"+suffix+tid.String(), "k"+suffix); err != nil {
				t.Fatalf("seed key: %v", err)
			}
		}
		insertKey(tenantA, ownerA, "1")
		insertKey(tenantA, adminA, "2")
		insertKey(tenantB, ownerB, "3")

		clientRef := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO mcp_oauth_clients (id, client_id, kind, name, redirect_uris)
			VALUES ($1, $2, 'dynamic', 'c', ARRAY['http://127.0.0.1/cb'])`, clientRef.String(), "client-"+clientRef.String()); err != nil {
			t.Fatalf("seed client: %v", err)
		}
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(ctx, `DELETE FROM mcp_oauth_clients WHERE id = $1`, clientRef.String())
		})
		for _, tid := range []shared.ID{tenantA, tenantB} {
			u := map[shared.ID]shared.ID{tenantA: ownerA, tenantB: ownerB}[tid]
			if _, err := sqlDB.ExecContext(ctx, `
				INSERT INTO mcp_oauth_grants (tenant_id, user_id, client_ref, resource, scopes, expires_at)
				VALUES ($1, $2, $3, 'https://api.example.test/mcp', ARRAY['findings:read'], NOW() + interval '1 day')`,
				tid.String(), u.String(), clientRef.String()); err != nil {
				t.Fatalf("seed grant: %v", err)
			}
		}

		keys, grants, err := repo.CountCredentials(ctx, tenantA)
		if err != nil || keys != 2 || grants != 1 {
			t.Fatalf("count: %d keys %d grants %v", keys, grants, err)
		}
		keys, grants, err = repo.RevokeCredentials(ctx, tenantA, ownerA)
		if err != nil || keys != 2 || grants != 1 {
			t.Fatalf("revoke: %d keys %d grants %v", keys, grants, err)
		}
		if k, g, _ := repo.CountCredentials(ctx, tenantA); k != 0 || g != 0 {
			t.Fatalf("still live after revoke: %d %d", k, g)
		}
		// The other organization is untouched.
		if k, g, _ := repo.CountCredentials(ctx, tenantB); k != 1 || g != 1 {
			t.Fatalf("org B affected: %d keys %d grants", k, g)
		}
	})
}
