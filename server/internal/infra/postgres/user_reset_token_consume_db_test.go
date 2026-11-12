package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A reset link is single use even when two requests present it at the same
// moment: the clear is one conditional UPDATE, so exactly one of them wins.
func TestUserRepository_ConsumePasswordResetTokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	db := testdb.PrivateDatabase(t, "reset_token_consume", "../../../migrations")
	repo := NewUserRepository(&DB{DB: db})

	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name, auth_provider, password_hash, password_reset_token, password_reset_expires_at)
		VALUES ($1, $2, 'u', 'local', 'h', 'hash-1', NOW() + interval '1 hour')`, id.String(), id.String()+"@reset.test"); err != nil {
		t.Fatal(err)
	}

	const n = 12
	var won atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.ConsumePasswordResetToken(ctx, id, "hash-1")
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			if ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d of %d concurrent submits consumed the token, want exactly 1", won.Load(), n)
	}
	if _, err := repo.GetByPasswordResetToken(ctx, "hash-1"); err == nil {
		t.Fatal("the token still resolves after it was consumed")
	}

	t.Run("a different or expired token consumes nothing", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE users SET password_reset_token = 'hash-2', password_reset_expires_at = NOW() + interval '1 hour' WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
		if ok, err := repo.ConsumePasswordResetToken(ctx, id, "other"); err != nil || ok {
			t.Fatalf("wrong hash: ok=%v err=%v", ok, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE users SET password_reset_expires_at = $2 WHERE id = $1`, id.String(), time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		if ok, err := repo.ConsumePasswordResetToken(ctx, id, "hash-2"); err != nil || ok {
			t.Fatalf("expired: ok=%v err=%v", ok, err)
		}
	})
}
