package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The daily evidence cap is counted inside the insert transaction under a
// per-tenant lock: concurrent writes on different findings of one tenant
// cannot pass it together, and another tenant is not counted.
func TestInsertManual_DailyCapHoldsUnderConcurrency_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	repo := NewFindingEvidenceRepository(&DB{DB: f.db})
	otherRepo := NewFindingEvidenceRepository(&DB{DB: other.db})
	ctx := context.Background()
	const limit, writers = 3, 10
	capWindow := evidencedom.DailyCap{Limit: limit, Since: time.Now().Add(-24 * time.Hour)}
	rec := func(seq string) []evidencedom.NewRecord {
		return []evidencedom.NewRecord{{Record: evidencedom.Record{
			ID: shared.NewID(), Kind: "http", ContentSHA256: "sha-" + seq, CapturedAt: time.Now(),
			Item: evidencedom.Item{Kind: "http"},
		}}}
	}

	findings := make([]shared.ID, writers)
	for i := range findings {
		findings[i] = f.finding(t, f.host, "nuclei", fmt.Sprintf("rule-%d", i), nil)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	stored, refused := 0, 0
	start := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			n, err := repo.InsertManual(ctx, f.tenant, findings[i], rec(fmt.Sprint(i)), capWindow)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				stored += n
			case errors.Is(err, evidencedom.ErrDailyCapReached):
				refused++
			default:
				t.Errorf("writer %d: %v", i, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if stored != limit || refused != writers-limit {
		t.Fatalf("stored %d refused %d, want %d / %d", stored, refused, limit, writers-limit)
	}
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM finding_evidence WHERE tenant_id = $1`, f.tenant.String()).Scan(&n); err != nil || n != limit {
		t.Fatalf("rows = %d (%v), want %d", n, err, limit)
	}

	// Another organization has its own budget.
	of := other.finding(t, other.host, "nuclei", "rule-x", nil)
	if got, err := otherRepo.InsertManual(ctx, other.tenant, of, rec("other"), capWindow); err != nil || got != 1 {
		t.Fatalf("other tenant: stored %d, %v", got, err)
	}
	// No cap (zero limit) stores as before.
	extra := f.finding(t, f.host, "nuclei", "rule-extra", nil)
	if got, err := repo.InsertManual(ctx, f.tenant, extra, rec("free"), evidencedom.DailyCap{}); err != nil || got != 1 {
		t.Fatalf("uncapped: stored %d, %v", got, err)
	}
}
