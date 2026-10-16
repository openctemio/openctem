package postgres

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

// The version check row: the first claim only schedules, one replica wins a
// due check, an older feed never replaces a newer one, failures count up and
// a success clears them.
func TestVersionCheckRepository_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	clean := func() { _, _ = db.Exec(`DELETE FROM version_check_state`) }
	clean()
	t.Cleanup(clean)
	repo := NewVersionCheckRepository(&DB{DB: db})
	now := time.Now().UTC().Truncate(time.Second)

	if st, err := repo.Get(ctx); err != nil || st.Feed != nil || st.NextCheckAt != nil {
		t.Fatalf("empty state: %+v %v", st, err)
	}
	if due, err := repo.ClaimDue(ctx, now, now.Add(10*time.Minute), now.Add(24*time.Hour)); err != nil || due {
		t.Fatalf("first claim must only schedule: %v %v", due, err)
	}

	// Ten replicas race for a due check: exactly one wins.
	later := now.Add(11 * time.Minute)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if due, err := repo.ClaimDue(ctx, later, later, later.Add(24*time.Hour)); err == nil && due {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d replicas won one check", wins.Load())
	}

	failures, err := repo.RecordFailure(ctx, "unreachable", later, func(n int) time.Time { return later.Add(time.Duration(n) * time.Hour) })
	if err != nil || failures != 1 {
		t.Fatalf("failure: %d %v", failures, err)
	}
	st, _ := repo.Get(ctx)
	if st.LastError != "unreachable" || !st.NextCheckAt.Equal(later.Add(time.Hour)) {
		t.Fatalf("after failure: %+v", st)
	}

	feed := func(seq uint64) *releasefeed.Verified {
		return &releasefeed.Verified{KeySetVersion: 2, Digest: strings.Repeat("a", 64), Feed: releasefeed.Feed{Kind: releasefeed.FeedKind, Sequence: seq, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			Releases: []releasefeed.Release{{Version: "v1.2.3", PublishedAt: now}}, Advisories: []releasefeed.Advisory{}}}
	}
	if ok, err := repo.Apply(ctx, feed(100), "online", later); err != nil || !ok {
		t.Fatalf("apply: %v %v", ok, err)
	}
	if ok, err := repo.Apply(ctx, feed(99), "import", later); err != nil || ok {
		t.Fatalf("an older feed replaced a newer one: %v %v", ok, err)
	}
	same := feed(100)
	same.Digest = strings.Repeat("b", 64)
	if ok, _ := repo.Apply(ctx, same, "import", later); ok {
		t.Fatal("another feed with the applied sequence was stored")
	}
	if ok, err := repo.Apply(ctx, feed(100), "import", later); err != nil || !ok {
		t.Fatalf("the identical feed again: %v %v", ok, err)
	}
	older := feed(101)
	older.KeySetVersion = 1
	if ok, _ := repo.Apply(ctx, older, "import", later); ok {
		t.Fatal("a feed under an older key set was stored")
	}
	st, _ = repo.Get(ctx)
	if st.AppliedSequence != 100 || st.KeySetVersion != 2 || st.Origin != "import" || st.FeedDigest != strings.Repeat("a", 64) || st.LastError != "" ||
		st.ConsecutiveFailures != 0 || st.Feed == nil || st.Feed.Releases[0].Version != "v1.2.3" {
		t.Fatalf("stored: %+v", st)
	}

	// An import before any scheduled check creates the row.
	clean()
	if ok, err := repo.Apply(ctx, feed(5), "import", now); err != nil || !ok {
		t.Fatalf("import into an empty table: %v %v", ok, err)
	}
}
