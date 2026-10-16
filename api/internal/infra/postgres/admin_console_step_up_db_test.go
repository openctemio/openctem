package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A verified console session records its step-up time and reads it back; a
// pending session (TOTP step not done) is never marked. Requires DATABASE_URL.
func TestAdminConsoleSessionStepUp_DB(t *testing.T) {
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
	if _, err := raw.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Step-up IT', 'super_admin')`,
		adminID, "stepup-"+adminID[:8]+"@example.com"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, adminID)
	})
	aid, _ := shared.IDFromString(adminID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := func(verified bool) *admin.Session {
		s := &admin.Session{ID: shared.NewID(), AdminID: aid, TokenHash: uuid.NewString(), MFAVerified: verified,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, AuthMethod: admin.AuthMethodPassword}
		if err := repo.CreateSession(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return s
	}

	verified := session(true)
	got, err := repo.GetSessionByTokenHash(ctx, verified.TokenHash)
	if err != nil || got.StepUpAt != nil {
		t.Fatalf("new session: step_up_at %v, err %v; want nil", got.StepUpAt, err)
	}
	if err := repo.MarkSessionStepUp(ctx, verified.ID, now); err != nil {
		t.Fatalf("mark: %v", err)
	}
	got, _ = repo.GetSessionByTokenHash(ctx, verified.TokenHash)
	if got.StepUpAt == nil || !got.StepUpAt.Equal(now) || !got.SteppedUp(now.Add(time.Minute)) {
		t.Fatalf("marked session: step_up_at %v, want %v inside the window", got.StepUpAt, now)
	}

	pending := session(false)
	if err := repo.MarkSessionStepUp(ctx, pending.ID, now); !errors.Is(err, admin.ErrSessionNotFound) {
		t.Fatalf("pending session marked: %v, want ErrSessionNotFound", err)
	}
	got, _ = repo.GetSessionByTokenHash(ctx, pending.TokenHash)
	if got.StepUpAt != nil {
		t.Fatal("a pending session must never carry a step-up time")
	}
}

// A step-up mark is spent by one fresh action: consuming clears it, a second
// consume finds nothing, and a mark older than the cut-off is not honored.
// Requires DATABASE_URL.
func TestAdminConsoleConsumeSessionStepUp_DB(t *testing.T) {
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
	if _, err := raw.ExecContext(ctx, `INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'Consume IT', 'super_admin')`,
		adminID, "consume-"+adminID[:8]+"@example.com"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() {
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, adminID)
	})
	aid, _ := shared.IDFromString(adminID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := &admin.Session{ID: shared.NewID(), AdminID: aid, TokenHash: uuid.NewString(), MFAVerified: true,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now, AuthMethod: admin.AuthMethodPassword}
	if err := repo.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}

	if ok, err := repo.ConsumeSessionStepUp(ctx, s.ID, now.Add(-time.Minute)); err != nil || ok {
		t.Fatalf("never stepped up: ok=%v err=%v", ok, err)
	}
	if err := repo.MarkSessionStepUp(ctx, s.ID, now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.ConsumeSessionStepUp(ctx, s.ID, now.Add(-time.Minute)); ok {
		t.Fatal("a mark older than the cut-off was honored")
	}
	if err := repo.MarkSessionStepUp(ctx, s.ID, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.ConsumeSessionStepUp(ctx, s.ID, now.Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("fresh mark: ok=%v err=%v", ok, err)
	}
	if ok, _ := repo.ConsumeSessionStepUp(ctx, s.ID, now.Add(-time.Minute)); ok {
		t.Fatal("a mark was spent twice")
	}
	got, _ := repo.GetSessionByTokenHash(ctx, s.TokenHash)
	if got.StepUpAt != nil {
		t.Fatal("consuming must clear the window too")
	}
}
