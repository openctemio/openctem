package threat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// pruneKEVRepo records PruneNotIn calls. Every method it does not override
// panics through the nil embedded interface, so the test also proves the
// prune touches nothing else.
type pruneKEVRepo struct {
	threatintel.KEVRepository
	count  int64
	pruned [][]string
}

func (r *pruneKEVRepo) Count(context.Context) (int64, error) { return r.count, nil }

func (r *pruneKEVRepo) PruneNotIn(_ context.Context, keep []string) (int64, error) {
	r.pruned = append(r.pruned, keep)
	return r.count - int64(len(keep)), nil
}

type pruneTIRepo struct {
	threatintel.ThreatIntelRepository
	kev *pruneKEVRepo
}

func (r *pruneTIRepo) KEV() threatintel.KEVRepository { return r.kev }

func kevEntries(n int) []*threatintel.KEVEntry {
	out := make([]*threatintel.KEVEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, threatintel.NewKEVEntry(fmt.Sprintf("CVE-2020-%05d", i),
			"v", "p", "n", "d", time.Now(), time.Now(), "Unknown", "", nil))
	}
	return out
}

// A CVE that CISA removed from KEV must leave kev_catalog, otherwise the
// catalog propagation and the findings reconciliation can never clear its
// known-exploited flags. Before this change SyncKEV only upserted.
func TestPruneRemovedKEV(t *testing.T) {
	cases := []struct {
		name      string
		catalog   int64
		feed      int
		wantPrune bool
	}{
		{"one CVE removed from a full catalog", 1500, 1499, true},
		{"nothing removed", 1500, 1500, false},
		{"feed larger than catalog", 1500, 1501, false},
		{"too many removals in absolute terms", 1500, 1500 - maxKEVRemovalsPerSync - 1, false},
		{"too large a share of a small catalog", 100, 97, false},
		{"empty feed never prunes", 1500, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kev := &pruneKEVRepo{count: tc.catalog}
			svc := &IntelService{repo: &pruneTIRepo{kev: kev}, logger: logger.NewNop()}
			svc.pruneRemovedKEV(context.Background(), kevEntries(tc.feed))
			if got := len(kev.pruned) == 1; got != tc.wantPrune {
				t.Fatalf("pruned=%v, want %v", got, tc.wantPrune)
			}
			if tc.wantPrune && len(kev.pruned[0]) != tc.feed {
				t.Fatalf("keep list has %d ids, want %d", len(kev.pruned[0]), tc.feed)
			}
		})
	}
}

// Repeated CVE ids in the feed count once, so a duplicate does not hide a
// removal from the guard or the keep list.
func TestPruneRemovedKEV_DeduplicatesFeed(t *testing.T) {
	kev := &pruneKEVRepo{count: 1500}
	svc := &IntelService{repo: &pruneTIRepo{kev: kev}, logger: logger.NewNop()}
	entries := kevEntries(1499)
	entries = append(entries, entries[0])
	svc.pruneRemovedKEV(context.Background(), entries)
	if len(kev.pruned) != 1 || len(kev.pruned[0]) != 1499 {
		t.Fatalf("want one prune keeping 1499 ids, got %d calls", len(kev.pruned))
	}
}
