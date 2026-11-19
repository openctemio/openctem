package threatalert

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/domain/vulnevent"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// fanOutStore implements the planner store methods the fan-out uses; any
// other call panics on the nil embedded interface.
type fanOutStore struct {
	threatalert.PlannerStore
	cursor   int64
	events   []vulnevent.Event
	affected map[string][]shared.ID
	lookups  [][]string
	log      []string // "enqueue:<vuln>" and "resolve:<vuln>" in call order
	queued   []threatalert.QueueItem
	groups   map[string]string                  // vuln id -> card id
	grouped  map[string][]threatalert.QueueItem // card id -> alerts grouped into it
}

func (s *fanOutStore) CardsGrouping(_ context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range ids {
		if c := s.groups[id]; c != "" {
			out[id] = c
		}
	}
	return out, nil
}

func (s *fanOutStore) GroupedInto(_ context.Context, cardID string) ([]threatalert.QueueItem, error) {
	return s.grouped[cardID], nil
}

func (s *fanOutStore) PlannerCursor(context.Context) (int64, error) { return s.cursor, nil }
func (s *fanOutStore) SetPlannerCursor(_ context.Context, id int64) error {
	s.cursor = id
	return nil
}

func (s *fanOutStore) EventsAfter(_ context.Context, id int64, limit int) ([]vulnevent.Event, error) {
	var out []vulnevent.Event
	for _, e := range s.events {
		if e.ID > id && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *fanOutStore) TenantsAffectedBy(_ context.Context, ids []string) (map[string][]shared.ID, error) {
	s.lookups = append(s.lookups, ids)
	out := map[string][]shared.ID{}
	for _, id := range ids {
		if t, ok := s.affected[id]; ok {
			out[id] = t
		}
	}
	return out, nil
}

func (s *fanOutStore) Enqueue(_ context.Context, items []threatalert.QueueItem) error {
	for _, it := range items {
		s.log = append(s.log, "enqueue:"+it.VulnID)
	}
	s.queued = append(s.queued, items...)
	return nil
}

func (s *fanOutStore) ResolveVuln(_ context.Context, vulnID, _ string, _ time.Time) (int, error) {
	s.log = append(s.log, "resolve:"+vulnID)
	return 0, nil
}

// A page of events costs one affected-tenants lookup, duplicates are queued
// once, a rejection resolves after the events before it are queued, and the
// cursor stops before a fresh gap in event ids.
func TestFanOutBatchesAPageAndStopsAtAGap(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	a, b := shared.NewID(), shared.NewID()
	old := now.Add(-time.Hour)
	st := &fanOutStore{
		events: []vulnevent.Event{
			{ID: 1, VulnID: "CVE-2099-0001", Kind: vulnevent.KindPublished, At: old},
			{ID: 2, VulnID: "CVE-2099-0001", Kind: vulnevent.KindRangesAdded, At: old},
			{ID: 3, VulnID: "CVE-2099-0002", Kind: vulnevent.KindPublished, At: old},
			{ID: 4, VulnID: "CVE-2099-0003", Kind: vulnevent.KindRejected, At: old},
			{ID: 5, VulnID: "CVE-2099-0004", Kind: vulnevent.KindPublished, At: old},
			// id 6 is missing and 7 is fresh: wait for 6.
			{ID: 7, VulnID: "CVE-2099-0005", Kind: vulnevent.KindPublished, At: now},
		},
		affected: map[string][]shared.ID{
			"CVE-2099-0001": {a, b},
			"CVE-2099-0002": {b},
			"CVE-2099-0004": {a},
			"CVE-2099-0005": {a},
		},
	}
	p := NewPlanner(st, nil, logger.NewNop())
	SetClockForTest(p, func() time.Time { return now })
	var stats Stats
	if err := p.fanOut(context.Background(), &stats, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(st.lookups) != 1 {
		t.Fatalf("lookups = %d, want 1 for the page", len(st.lookups))
	}
	if got := len(st.lookups[0]); got != 4 {
		t.Fatalf("looked up %d vulnerabilities, want 4 (no rejection, nothing after the gap)", got)
	}
	if st.cursor != 5 || stats.Events != 5 {
		t.Fatalf("cursor %d, events %d; want 5 and 5", st.cursor, stats.Events)
	}
	want := []string{"enqueue:CVE-2099-0001", "enqueue:CVE-2099-0001", "enqueue:CVE-2099-0002",
		"resolve:CVE-2099-0003", "enqueue:CVE-2099-0004"}
	if len(st.log) != len(want) {
		t.Fatalf("calls = %v, want %v", st.log, want)
	}
	for i := range want {
		if st.log[i] != want[i] {
			t.Fatalf("calls = %v, want %v", st.log, want)
		}
	}

	// Once the gap is old enough the rest goes.
	SetClockForTest(p, func() time.Time { return now.Add(time.Hour) })
	if err := p.fanOut(context.Background(), &stats, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st.cursor != 7 || len(st.queued) != 5 {
		t.Fatalf("after the gap: cursor %d, queued %d; want 7 and 5", st.cursor, len(st.queued))
	}
}

// The vulnerabilities a card groups are queued as the card (one alert per
// organization and card); a withdrawn card resolves its alerts and queues
// the vulnerabilities it had grouped on their own again.
func TestFanOutGroupsByCardAndWithdraws(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	a, b := shared.NewID(), shared.NewID()
	st := &fanOutStore{
		events: []vulnevent.Event{
			{ID: 1, VulnID: "CVE-2026-90001", Kind: vulnevent.KindPublished, At: old},
			{ID: 2, VulnID: "CVE-2026-90002", Kind: vulnevent.KindPublished, At: old},
			{ID: 3, VulnID: "OCA-2026-9001", Kind: vulnevent.KindCardPublished, At: old},
			{ID: 4, VulnID: "OCA-2026-9002", Kind: vulnevent.KindCardWithdrawn, At: old},
		},
		affected: map[string][]shared.ID{"CVE-2026-90001": {a}, "CVE-2026-90002": {a, b}, "OCA-2026-9001": {a, b}},
		groups:   map[string]string{"CVE-2026-90001": "OCA-2026-9001", "CVE-2026-90002": "OCA-2026-9001"},
		grouped:  map[string][]threatalert.QueueItem{"OCA-2026-9002": {{TenantID: b, VulnID: "CVE-2026-80001"}}},
	}
	p := NewPlanner(st, nil, logger.NewNop())
	SetClockForTest(p, func() time.Time { return now })
	var stats Stats
	if err := p.fanOut(context.Background(), &stats, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range st.lookups[0] {
		if id == "OCA-2026-9002" {
			t.Fatal("a withdrawn card was looked up as affecting anyone")
		}
	}
	want := map[threatalert.QueueItem]bool{
		{TenantID: a, VulnID: "OCA-2026-9001"}:  true,
		{TenantID: b, VulnID: "OCA-2026-9001"}:  true,
		{TenantID: b, VulnID: "CVE-2026-80001"}: true,
	}
	got := map[threatalert.QueueItem]bool{}
	for _, it := range st.queued {
		if it.VulnID == "CVE-2026-90001" || it.VulnID == "CVE-2026-90002" {
			t.Fatalf("a grouped vulnerability was queued on its own: %v", it)
		}
		got[it] = true
	}
	if len(got) != len(want) {
		t.Fatalf("queued %v, want %v", st.queued, want)
	}
	for it := range want {
		if !got[it] {
			t.Fatalf("missing %v in %v", it, st.queued)
		}
	}
	if !slices.Contains(st.log, "resolve:OCA-2026-9002") {
		t.Fatalf("withdrawn card not resolved: %v", st.log)
	}
}

// A revision that drops a vulnerability from the card (or a card that is no
// longer reviewed) queues the alerts grouped into it for that vulnerability
// on their own again; the ones the card still groups stay with the card.
func TestFanOutCardUpdateRequeuesRemovedVulns(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	a := shared.NewID()
	st := &fanOutStore{
		events:   []vulnevent.Event{{ID: 1, VulnID: "OCA-2026-9001", Kind: vulnevent.KindCardUpdated, At: now.Add(-time.Hour)}},
		affected: map[string][]shared.ID{"OCA-2026-9001": {a}},
		// Revision 2 keeps CVE-2026-90001 and drops CVE-2026-90002.
		groups: map[string]string{"CVE-2026-90001": "OCA-2026-9001"},
		grouped: map[string][]threatalert.QueueItem{"OCA-2026-9001": {
			{TenantID: a, VulnID: "CVE-2026-90001"}, {TenantID: a, VulnID: "CVE-2026-90002"}}},
	}
	p := NewPlanner(st, nil, logger.NewNop())
	SetClockForTest(p, func() time.Time { return now })
	var stats Stats
	if err := p.fanOut(context.Background(), &stats, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, it := range st.queued {
		got[it.VulnID] = true
	}
	if !got["CVE-2026-90002"] {
		t.Fatalf("a vulnerability removed from the card was not requeued: %v", st.queued)
	}
	if got["CVE-2026-90001"] {
		t.Fatalf("a vulnerability the card still groups was requeued on its own: %v", st.queued)
	}
	if !got["OCA-2026-9001"] {
		t.Fatalf("the card itself was not replanned: %v", st.queued)
	}
}
