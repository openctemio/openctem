package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EndOldestVerifiedSessions keeps the newest verified sessions of one admin,
// leaves pending sessions and other admins' sessions alone. Requires DATABASE_URL.
func TestAdminConsoleEndOldestVerifiedSessions_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	repo := NewAdminConsoleRepository(&DB{DB: raw})

	seedAdmin := func() shared.ID {
		id := uuid.NewString()
		if _, err := raw.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Cap IT', 'super_admin')`,
			id, "cap-"+id[:8]+"@example.com"); err != nil {
			t.Fatalf("seed admin: %v", err)
		}
		t.Cleanup(func() {
			_, _ = raw.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, id)
			_, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, id)
		})
		sid, _ := shared.IDFromString(id)
		return sid
	}
	a, other := seedAdmin(), seedAdmin()
	base := time.Now().UTC().Truncate(time.Microsecond)
	add := func(adm shared.ID, verified bool, age time.Duration) string {
		hash := uuid.NewString()
		at := base.Add(-age)
		if err := repo.CreateSession(ctx, &admin.Session{ID: shared.NewID(), AdminID: adm, TokenHash: hash, MFAVerified: verified,
			CreatedAt: at, ExpiresAt: at.Add(time.Hour), LastSeenAt: at, AuthMethod: admin.AuthMethodPassword}); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return hash
	}
	oldest := add(a, true, 4*time.Minute)
	older := add(a, true, 3*time.Minute)
	mid := add(a, true, 2*time.Minute)
	newest := add(a, true, time.Minute)
	pending := add(a, false, 10*time.Minute)
	others := add(other, true, 10*time.Minute)

	n, err := repo.EndOldestVerifiedSessions(ctx, a, 3)
	if err != nil || n != 1 {
		t.Fatalf("ended %d, err %v; want 1", n, err)
	}
	exists := func(h string) bool { _, err := repo.GetSessionByTokenHash(ctx, h); return err == nil }
	if exists(oldest) {
		t.Fatal("the oldest verified session must be gone")
	}
	for name, h := range map[string]string{"older": older, "mid": mid, "newest": newest, "pending": pending, "other admin": others} {
		if !exists(h) {
			t.Fatalf("%s session must stay", name)
		}
	}
	if n, err := repo.EndOldestVerifiedSessions(ctx, a, 3); err != nil || n != 0 {
		t.Fatalf("second call ended %d, err %v; want 0", n, err)
	}
}
