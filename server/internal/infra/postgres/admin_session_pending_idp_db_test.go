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

// A pending console session carries the IdP identity to bind after the second
// factor and reads it back; a verified session can never carry one (database
// constraint). Requires DATABASE_URL.
func TestAdminSessionPendingIdPBinding_DB(t *testing.T) {
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

	adminID := uuid.NewString()
	if _, err := raw.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Pending IdP IT', 'super_admin')`,
		adminID, "pendingidp-"+adminID[:8]+"@example.com"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, adminID)
	})
	aid, _ := shared.IDFromString(adminID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := func(verified bool, iss, sub string) (*admin.Session, error) {
		s := &admin.Session{ID: shared.NewID(), AdminID: aid, TokenHash: uuid.NewString(), MFAVerified: verified,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, AuthMethod: admin.AuthMethodIdP,
			PendingIdPIssuer: iss, PendingIdPSubject: sub}
		return s, repo.CreateSession(ctx, s)
	}

	pending, err := session(false, "https://idp.example.com", "sub-1")
	if err != nil {
		t.Fatalf("create pending session: %v", err)
	}
	got, err := repo.GetSessionByTokenHash(ctx, pending.TokenHash)
	if err != nil || got.PendingIdPIssuer != "https://idp.example.com" || got.PendingIdPSubject != "sub-1" {
		t.Fatalf("pending binding round trip: %+v, %v", got, err)
	}
	plain, err := session(false, "", "")
	if err != nil {
		t.Fatalf("create plain session: %v", err)
	}
	if got, err := repo.GetSessionByTokenHash(ctx, plain.TokenHash); err != nil || got.PendingIdPSubject != "" {
		t.Fatalf("plain session: %+v, %v", got, err)
	}
	if _, err := session(true, "https://idp.example.com", "sub-1"); err == nil {
		t.Fatal("a verified session must not carry a pending binding")
	}
	if _, err := session(false, "https://idp.example.com", ""); err == nil {
		t.Fatal("issuer without subject must be refused")
	}
}
