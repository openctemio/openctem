package postgres

import (
	"context"
	"testing"
	"time"
)

// HasPendingInvitationForEmail answers yes only for a pending, unexpired
// invitation (any organization, case-insensitive email), as the application
// role. Requires DATABASE_URL.
func TestTenantRepository_HasPendingInvitationForEmail(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	r := NewTenantRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	inviter := seedUser(ctx, t, db)

	insert := func(email string, expires time.Time, accepted bool) {
		t.Helper()
		var acceptedAt any
		if accepted {
			acceptedAt = time.Now()
		}
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO tenant_invitations (tenant_id, email, role, token, invited_by, expires_at, accepted_at)
			VALUES ($1, $2, 'viewer', md5(random()::text), $3, $4, $5)`,
			tenant.String(), email, inviter.String(), expires, acceptedAt); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}
	}
	insert("Pending.User@Example.com", time.Now().Add(24*time.Hour), false)
	insert("expired@example.com", time.Now().Add(-time.Hour), false)
	insert("accepted@example.com", time.Now().Add(24*time.Hour), true)

	for email, want := range map[string]bool{
		"pending.user@example.com": true, // case-insensitive
		"expired@example.com":      false,
		"accepted@example.com":     false,
		"nobody@example.com":       false,
	} {
		got, err := r.HasPendingInvitationForEmail(ctx, email)
		if err != nil {
			t.Fatalf("%s: %v", email, err)
		}
		if got != want {
			t.Errorf("%s: got %v, want %v", email, got, want)
		}
	}
}
