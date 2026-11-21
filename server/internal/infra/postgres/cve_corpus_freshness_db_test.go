package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The freshness watch reads the newest publication date and the 24-hour and
// prior-30-day counts. A date far in the future is used as "now" so only
// this test's rows fall in the windows of a shared test database.
func TestCVECorpusFreshnessStats(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	now := time.Date(2098, 6, 1, 12, 0, 0, 0, time.UTC)
	base := 20000 + time.Now().UnixNano()%9000000
	rows := []time.Duration{
		-time.Hour, -5 * time.Hour, // last 24 h
		-30 * time.Hour, -10 * 24 * time.Hour, -29 * 24 * time.Hour, // prior 30 days
		-40 * 24 * time.Hour, // outside both windows
		2 * time.Hour,        // in the future: ignored
	}
	ids := make([]string, 0, len(rows))
	for i, d := range rows {
		id := fmt.Sprintf("CVE-2098-%d", base+int64(i))
		ids = append(ids, id)
		if _, err := db.ExecContext(ctx, `INSERT INTO cve_records (cve_id, published_at) VALUES ($1, $2)`, id, now.Add(d)); err != nil {
			t.Fatal(err)
		}
	}
	cleanupCVE(t, db, ids...)

	got, err := NewCVECorpusRepository(&DB{DB: db}).FreshnessStats(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.NewestPublished == nil || !got.NewestPublished.Equal(now.Add(-time.Hour)) {
		t.Fatalf("newest: %v", got.NewestPublished)
	}
	if got.Published24h != 2 || got.PublishedPrior30d != 3 {
		t.Fatalf("counts: %+v", got)
	}
}
