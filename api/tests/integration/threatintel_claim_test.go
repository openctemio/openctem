package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
)

// One run per feed: of any number of simultaneous claims exactly one wins,
// a finished run frees the feed, and a run stuck "running" past the timeout
// can be claimed again.
func TestSyncStatusTryStart_OneRunAtATime(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	repo := postgres.NewThreatIntelRepository(&postgres.DB{DB: db}).SyncStatus()
	reset := func() {
		_, err := db.Exec(`UPDATE threat_intel_sync_status SET last_sync_status = 'success' WHERE source_name = 'kev'`)
		require.NoError(t, err)
	}
	reset()
	t.Cleanup(reset)

	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.TryStart(ctx, "kev", time.Hour)
			assert.NoError(t, err)
			if ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, won.Load(), "exactly one simultaneous claim wins")

	st, err := repo.GetBySource(ctx, "kev")
	require.NoError(t, err)
	assert.Equal(t, "running", st.LastSyncStatus().String())

	// Held: not claimable.
	ok, err := repo.TryStart(ctx, "kev", time.Hour)
	require.NoError(t, err)
	assert.False(t, ok)

	// Stuck past the timeout: claimable again (a trigger stamps updated_at,
	// so the test waits instead of back-dating the row).
	time.Sleep(60 * time.Millisecond)
	ok, err = repo.TryStart(ctx, "kev", 20*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, ok)

	// Finished (the run writes its outcome): free.
	st, err = repo.GetBySource(ctx, "kev")
	require.NoError(t, err)
	st.MarkSyncUnchanged(1, 0)
	require.NoError(t, repo.Update(ctx, st))
	ok, err = repo.TryStart(ctx, "kev", time.Hour)
	require.NoError(t, err)
	assert.True(t, ok)

	// Unknown source: nothing to claim.
	ok, err = repo.TryStart(ctx, "nope", time.Hour)
	require.NoError(t, err)
	assert.False(t, ok)
}
