package handler

// Forgot-password on an installation that cannot send email issues nothing:
// a token it cannot send would replace the account's stored link, which is
// also where an administrator's one-time setup or reset link lives
// (docs/architecture/user-onboarding.md, "Running without email").
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestForgotPassword_NoEmail_KeepsHandedOverLink_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	userRepo := postgres.NewUserRepository(pg)
	cfg := config.AuthConfig{JWTSecret: "forgot-no-email-test-secret-0123456789abcdef", JWTIssuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		PasswordResetDuration: time.Hour}
	authSvc := auth.NewAuthService(userRepo, postgres.NewSessionRepository(raw), postgres.NewRefreshTokenRepository(raw),
		postgres.NewTenantRepository(pg), auditapp.NewAuditService(postgres.NewAuditRepository(pg), log), cfg, log)
	// No email service at all: the server cannot send email.
	h := NewLocalAuthHandler(authSvc, nil, nil, cfg, log)

	id := uuid.NewString()
	addr := "forgot-" + id[:8] + "@it.test"
	handedOver := "handed-over-" + id
	if _, err := raw.ExecContext(context.Background(), `INSERT INTO users (id, email, name, auth_provider, password_reset_token, password_reset_expires_at)
		VALUES ($1, $2, 'Pending owner', 'local', $3, now() + interval '1 day')`, id, addr, crypto.HashToken(handedOver)); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	t.Cleanup(func() { _, _ = raw.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/forgot-password", strings.NewReader(`{"email":"`+addr+`"}`))
	rec := httptest.NewRecorder()
	h.ForgotPassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d (%s): the answer must not change", rec.Code, rec.Body.String())
	}
	// The issue would run after the response: give it time to happen.
	time.Sleep(500 * time.Millisecond)

	var stored sql.NullString
	if err := raw.QueryRowContext(context.Background(), `SELECT password_reset_token FROM users WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.String != crypto.HashToken(handedOver) {
		t.Fatal("forgot-password without email replaced the link an administrator handed over")
	}
	if err := authSvc.ResetPassword(context.Background(), auth.ResetPasswordInput{Token: handedOver, NewPassword: "Correct-Horse-Battery-9"}); err != nil {
		t.Fatalf("handed-over link no longer works: %v", err)
	}
}
