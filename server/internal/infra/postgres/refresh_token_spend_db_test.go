package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// research/189 B1a-2: rotation used to read the token, check used_at in
// memory, then write used_at unconditionally, so two concurrent refreshes of
// one token both succeeded and forked the family without tripping reuse
// detection. The spend is now one conditional update: exactly one caller wins.
func TestRefreshTokenRepository_MarkUsedIfUnusedIsRaceFree(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewRefreshTokenRepository(db)
	userID := seedGroupsUser(ctx, t, db, "spend.test")
	sessionID, tokenID, revokedID := shared.NewID(), shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, access_token_hash, expires_at)
		VALUES ($1, $2, $3, NOW() + interval '1 hour')`, sessionID.String(), userID.String(), "spend-"+sessionID.String()[:20]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, session_id, token_hash, family, expires_at, revoked_at)
		VALUES ($1, $3, $4, $5, $1, NOW() + interval '1 hour', NULL),
		       ($2, $3, $4, $6, $2, NOW() + interval '1 hour', NOW())`,
		tokenID.String(), revokedID.String(), userID.String(), sessionID.String(),
		"spend-a-"+tokenID.String()[:20], "spend-b-"+revokedID.String()[:20]); err != nil {
		t.Fatal(err)
	}

	const n = 10
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.MarkUsedIfUnused(ctx, tokenID)
			if err != nil {
				t.Errorf("spend: %v", err)
				return
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("%d concurrent spends of one token: %d won, want exactly 1", n, got)
	}
	if ok, err := repo.MarkUsedIfUnused(ctx, revokedID); err != nil || ok {
		t.Fatalf("spend of a revoked token: ok=%v err=%v, want false", ok, err)
	}
}
