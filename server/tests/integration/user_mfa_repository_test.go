package integration

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestUserMFARepository checks the SQL-level guarantees the 2FA service
// relies on: replay protection by compare-and-set on the time step, single-use
// recovery codes and challenges under concurrency, and atomic activation.
func TestUserMFARepository(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping user MFA repository test")
	}
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil || sqlDB.Ping() != nil {
		t.Skip("database not available")
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	var exists bool
	if err := sqlDB.QueryRow(`SELECT to_regclass('public.user_mfa') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skip("user_mfa missing: run migration 000228")
	}
	db := &postgres.DB{DB: sqlDB}
	repo := postgres.NewUserMFARepository(db)
	ctx := context.Background()

	userID := shared.NewID()
	if _, err := sqlDB.Exec(`INSERT INTO users (id, email, name, auth_provider, status, email_verified)
		VALUES ($1, $2, 'MFA Repo Test', 'local', 'active', true)`, userID.String(), "mfa-repo-"+userID.String()[28:]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, userID.String()) })

	if _, err := repo.GetFactor(ctx, userID); err == nil {
		t.Fatal("expected ErrFactorNotFound before setup")
	}
	if ok, err := repo.Activate(ctx, userID, 1, nil); err != nil || ok {
		t.Fatalf("activate without pending secret must be a no-op: ok=%v err=%v", ok, err)
	}
	if err := repo.SavePendingSecret(ctx, userID, "enc-secret"); err != nil {
		t.Fatalf("SavePendingSecret: %v", err)
	}
	if ok, _ := repo.AdvanceStep(ctx, userID, 100); ok {
		t.Fatal("a pending (not enabled) factor must not accept codes")
	}
	ok, err := repo.Activate(ctx, userID, 100, []string{"h1", "h2", "h3"})
	if err != nil || !ok {
		t.Fatalf("Activate: ok=%v err=%v", ok, err)
	}
	f, err := repo.GetFactor(ctx, userID)
	if err != nil || !f.Enabled || f.SecretEncrypted != "enc-secret" || f.PendingSecretEncrypted != "" || f.LastUsedStep != 100 {
		t.Fatalf("factor after activate: %+v err=%v", f, err)
	}

	// Replay: same or older step rejected; concurrent use of one new step wins once.
	if ok, _ := repo.AdvanceStep(ctx, userID, 100); ok {
		t.Fatal("same step accepted twice")
	}
	if ok, _ := repo.AdvanceStep(ctx, userID, 99); ok {
		t.Fatal("older step accepted")
	}
	wins := raceCount(20, func() bool { ok, _ := repo.AdvanceStep(ctx, userID, 101); return ok })
	if wins != 1 {
		t.Fatalf("concurrent use of one step succeeded %d times, want 1", wins)
	}

	// Recovery codes: single use under concurrency.
	codes, err := repo.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil || len(codes) != 3 {
		t.Fatalf("ListUnusedRecoveryCodes: %d %v", len(codes), err)
	}
	wins = raceCount(20, func() bool { ok, _ := repo.ConsumeRecoveryCode(ctx, userID, codes[0].ID); return ok })
	if wins != 1 {
		t.Fatalf("recovery code consumed %d times, want 1", wins)
	}
	if ok, _ := repo.ConsumeRecoveryCode(ctx, shared.NewID(), codes[1].ID); ok {
		t.Fatal("another user consumed this user's recovery code")
	}
	if left, _ := repo.ListUnusedRecoveryCodes(ctx, userID); len(left) != 2 {
		t.Fatalf("unused codes = %d, want 2", len(left))
	}
	if err := repo.ReplaceRecoveryCodes(ctx, userID, []string{"n1"}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	if left, _ := repo.ListUnusedRecoveryCodes(ctx, userID); len(left) != 1 || left[0].CodeHash != "n1" {
		t.Fatalf("after replace: %+v", left)
	}

	// Challenges: hashed lookup, attempts counter, single use, expiry.
	now := time.Now().UTC()
	c := &mfa.Challenge{
		ID: shared.NewID(), UserID: userID, TokenHash: crypto.HashToken("tok-" + userID.String()),
		Purpose: mfa.PurposeVerify, IPAddress: "203.0.113.9", UserAgent: "ua",
		ExpiresAt: now.Add(mfa.ChallengeTTL), CreatedAt: now,
	}
	if err := repo.CreateChallenge(ctx, c); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	got, err := repo.GetChallengeByTokenHash(ctx, c.TokenHash)
	if err != nil || got.Purpose != mfa.PurposeVerify || !got.UserID.Equals(userID) || got.ConsumedAt != nil {
		t.Fatalf("GetChallengeByTokenHash: %+v %v", got, err)
	}
	if n, _ := repo.RecordChallengeAttempt(ctx, c.ID); n != 1 {
		t.Fatalf("attempts = %d, want 1", n)
	}
	wins = raceCount(20, func() bool { ok, _ := repo.ConsumeChallenge(ctx, c.ID); return ok })
	if wins != 1 {
		t.Fatalf("challenge consumed %d times, want 1", wins)
	}
	expired := &mfa.Challenge{
		ID: shared.NewID(), UserID: userID, TokenHash: crypto.HashToken("exp-" + userID.String()),
		Purpose: mfa.PurposeEnroll, ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-6 * time.Minute),
	}
	if err := repo.CreateChallenge(ctx, expired); err != nil {
		t.Fatalf("CreateChallenge(expired): %v", err)
	}
	if ok, _ := repo.ConsumeChallenge(ctx, expired.ID); ok {
		t.Fatal("expired challenge consumed")
	}
	if err := repo.CreateChallenge(ctx, &mfa.Challenge{ID: shared.NewID(), UserID: userID, TokenHash: "x", Purpose: "bogus", ExpiresAt: now, CreatedAt: now}); err == nil {
		t.Fatal("unknown purpose accepted")
	}

	// Disable removes the factor and the codes.
	if err := repo.Disable(ctx, userID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := repo.GetFactor(ctx, userID); err == nil {
		t.Fatal("factor still present after Disable")
	}
	if left, _ := repo.ListUnusedRecoveryCodes(ctx, userID); len(left) != 0 {
		t.Fatalf("recovery codes survived Disable: %d", len(left))
	}
}

func raceCount(n int, fn func() bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fn() {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return wins
}
