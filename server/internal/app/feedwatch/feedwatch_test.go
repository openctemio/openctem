package feedwatch

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/logger"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func ptr(t time.Time) *time.Time { return &t }

// bundleView is an enabled bundle feed that applied a bundle created at
// asOf and last succeeded at ok.
func bundleView(asOf, ok time.Time) feedstatus.View {
	return feedstatus.View{Source: feedstatus.SourceVulnfeed, Enabled: true, State: feedstatus.StateUpToDate,
		LastSyncStatus: "success", LastSuccessAt: ptr(ok), DataAsOf: ptr(asOf), Interval: feedstatus.IntervalVulnfeed,
		Bundle: &feedstatus.BundleDetail{AppliedSequence: 93, BundleCreatedAt: ptr(asOf)}}
}

func kevView(ok time.Time) feedstatus.View {
	return feedstatus.View{Source: feedstatus.SourceKEV, Enabled: true, State: feedstatus.StateUpToDate,
		LastSyncStatus: "success", LastSuccessAt: ptr(ok), Interval: feedstatus.IntervalKEV}
}

func keys(cs []Condition) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Key)
	}
	slices.Sort(out)
	return out
}

func TestEvaluate(t *testing.T) {
	now := t0
	first := now.Add(-24 * time.Hour)
	fresh := []feedstatus.View{bundleView(now.Add(-time.Hour), now.Add(-10*time.Minute)), kevView(now.Add(-time.Hour))}
	healthy := &CorpusStats{NewestPublished: ptr(now.Add(-2 * time.Hour)), Published24h: 250, PublishedPrior30d: 30 * 280}

	refused := bundleView(now.Add(-3*time.Hour), now.Add(-3*time.Hour))
	refused.State, refused.LastSyncStatus, refused.ErrorCode = feedstatus.StateRefused, "failed", feedstatus.CodeExpired
	refused.FailingSince = ptr(now.Add(-5 * time.Minute))

	failingShort := bundleView(now.Add(-time.Hour), now.Add(-time.Hour))
	failingShort.State, failingShort.LastSyncStatus = feedstatus.StateFailing, "failed"
	failingShort.FailingSince = ptr(now.Add(-35 * time.Minute))
	failingLong := failingShort
	failingLong.FailingSince = ptr(now.Add(-41 * time.Minute))

	// v0.21.0: every run refused an expired bundle while the data aged.
	staleFailing := bundleView(now.Add(-13*time.Hour), now.Add(-13*time.Hour))
	staleFailing.State, staleFailing.LastSyncStatus = feedstatus.StateStale, "failed"
	staleFailing.FailingSince = ptr(now.Add(-13 * time.Hour))

	off := bundleView(now.Add(-100*time.Hour), now.Add(-100*time.Hour))
	off.Enabled, off.State = false, feedstatus.StateOff

	never := feedstatus.View{Source: feedstatus.SourceVulnfeed, Enabled: true, State: feedstatus.StateStale,
		LastSyncStatus: "pending", Interval: feedstatus.IntervalVulnfeed}

	cases := []struct {
		name  string
		views []feedstatus.View
		stats *CorpusStats
		first time.Time
		want  []string
	}{
		{"healthy", fresh, healthy, first, nil},
		{"bundle 13h old", []feedstatus.View{bundleView(now.Add(-13*time.Hour), now.Add(-5*time.Minute))}, healthy, first,
			[]string{"data_stale:vulnfeed"}},
		{"bundle 11h old", []feedstatus.View{bundleView(now.Add(-11*time.Hour), now.Add(-5*time.Minute))}, healthy, first, nil},
		{"KEV 7h without a success", []feedstatus.View{kevView(now.Add(-7 * time.Hour))}, nil, first, []string{"data_stale:kev"}},
		{"switched off", []feedstatus.View{off}, nil, first, nil},
		{"never loaded, inside the grace", []feedstatus.View{never}, nil, now.Add(-time.Hour), nil},
		{"never loaded, after the grace", []feedstatus.View{never}, nil, now.Add(-3 * time.Hour), []string{"data_stale:vulnfeed"}},
		{"refused alerts at once", []feedstatus.View{refused}, nil, first, []string{"import_refused:vulnfeed"}},
		{"failing one run", []feedstatus.View{failingShort}, nil, first, nil},
		{"failing two runs", []feedstatus.View{failingLong}, nil, first, []string{"import_failing:vulnfeed"}},
		{"stale and failing (the silent case)", []feedstatus.View{staleFailing}, nil, first,
			[]string{"data_stale:vulnfeed", "import_failing:vulnfeed"}},
		{"newest record 13h old", fresh, &CorpusStats{NewestPublished: ptr(now.Add(-13 * time.Hour)), Published24h: 250, PublishedPrior30d: 8400}, first,
			[]string{"newest_record_old"}},
		{"daily volume collapsed", fresh, &CorpusStats{NewestPublished: ptr(now.Add(-time.Hour)), Published24h: 40, PublishedPrior30d: 8400}, first,
			[]string{"volume_low"}},
		{"small corpus has no volume check", fresh, &CorpusStats{NewestPublished: ptr(now.Add(-time.Hour)), Published24h: 0, PublishedPrior30d: 300}, first, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := keys(Evaluate(c.views, c.stats, c.first, now))
			if !slices.Equal(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Banner conditions are the ones about data age; an import problem alone
// alerts the administrators but does not tell every user.
func TestEvaluateBannerFlag(t *testing.T) {
	now := t0
	refused := bundleView(now.Add(-time.Hour), now.Add(-time.Hour))
	refused.State = feedstatus.StateRefused
	cs := Evaluate([]feedstatus.View{refused, kevView(now.Add(-8 * time.Hour))},
		&CorpusStats{NewestPublished: ptr(now.Add(-20 * time.Hour)), Published24h: 10, PublishedPrior30d: 8400}, now.Add(-time.Hour*24), now)
	want := map[string]bool{"import_refused:vulnfeed": false, "data_stale:kev": true, "newest_record_old": true, "volume_low": false}
	for _, c := range cs {
		if b, ok := want[c.Key]; !ok || b != c.Banner {
			t.Fatalf("%s banner=%v", c.Key, c.Banner)
		}
	}
	if len(cs) != len(want) {
		t.Fatalf("got %v", keys(cs))
	}
}

type fakeFeeds struct {
	views []feedstatus.View
	err   error
}

func (f *fakeFeeds) FeedViews(context.Context) ([]feedstatus.View, error) { return f.views, f.err }

type fakeCorpus struct {
	stats CorpusStats
	calls int
}

func (f *fakeCorpus) FreshnessStats(context.Context, time.Time) (CorpusStats, error) {
	f.calls++
	return f.stats, nil
}

type fixture struct {
	now    time.Time
	feeds  *fakeFeeds
	corpus *fakeCorpus
	n      *consolesettingtest.Notifier
	repo   *consolesettingtest.Repo
	svc    *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: t0, feeds: &fakeFeeds{}, corpus: &fakeCorpus{}, n: &consolesettingtest.Notifier{},
		repo: consolesettingtest.NewRepo()}
	f.svc = New(f.feeds, f.corpus, f.repo, logger.NewNop())
	f.svc.SetClock(func() time.Time { return f.now })
	f.svc.SetNotifier(f.n)
	return f
}

func (f *fixture) tick(t *testing.T, d time.Duration) {
	t.Helper()
	f.now = f.now.Add(d)
	if _, err := f.svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) banner(t *testing.T) Banner {
	t.Helper()
	b, err := f.svc.Banner(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The case that went unnoticed for three days: every import is refused
// (an expired pointer) while the data ages. The refusal itself alerts at
// once, the stale data alerts and raises the banner at 12 hours, nothing is
// repeated on later checks, and recovery sends one "resolved" message and
// drops the banner.
func TestCheckRefusedFeedIsLoudAndRecovers(t *testing.T) {
	f := newFixture(t)
	applied := t0.Add(-time.Hour)
	refused := func() feedstatus.View {
		v := bundleView(applied, applied)
		v.State, v.LastSyncStatus, v.ErrorCode = feedstatus.StateRefused, "failed", feedstatus.CodeExpired
		v.FailingSince = ptr(applied.Add(20 * time.Minute))
		// feedstatus.Compute keeps a refused feed "refused" however old
		// its data gets.
		return v
	}
	f.corpus.stats = CorpusStats{NewestPublished: ptr(applied), Published24h: 280, PublishedPrior30d: 8400}

	f.feeds.views = []feedstatus.View{refused()}
	f.tick(t, 0)
	if f.n.Count() != 1 || !strings.HasPrefix(f.n.Subjects[0], "[CRITICAL]") || !strings.Contains(f.n.Bodies[0], "expired") {
		t.Fatalf("refusal not alerted at once: %v %v", f.n.Subjects, f.n.Bodies)
	}
	if b := f.banner(t); b.Stale {
		t.Fatalf("banner while the data is still current: %+v", b)
	}
	for range 6 { // an hour of checks: nothing new
		f.feeds.views = []feedstatus.View{refused()}
		f.tick(t, CheckEvery)
	}
	if f.n.Count() != 1 {
		t.Fatalf("repeated: %v", f.n.Subjects)
	}

	f.now = applied.Add(12*time.Hour + time.Minute)
	f.feeds.views = []feedstatus.View{refused()}
	f.tick(t, 0)
	if f.n.Count() != 2 || !strings.Contains(f.n.Bodies[1], "data is 12 hours old") || !strings.Contains(f.n.Bodies[1], "newest CVE record") {
		t.Fatalf("stale not alerted: %v %v", f.n.Subjects, f.n.Bodies)
	}
	b := f.banner(t)
	if !b.Stale || !slices.Equal(b.Codes, []string{CodeDataStale, CodeNewestRecordOld}) || b.StaleSince == nil || !b.StaleSince.Equal(applied) {
		t.Fatalf("banner: %+v", b)
	}

	// Recovered: a new bundle applied, a new record published.
	f.now = f.now.Add(CheckEvery)
	f.feeds.views = []feedstatus.View{bundleView(f.now.Add(-time.Hour), f.now)}
	f.corpus.stats.NewestPublished = ptr(f.now.Add(-time.Hour))
	f.tick(t, 0)
	if f.n.Count() != 3 || f.n.Subjects[2] != "Threat intelligence feeds: resolved" {
		t.Fatalf("resolved: %v", f.n.Subjects)
	}
	if b := f.banner(t); b.Stale || b.DataAsOf == nil {
		t.Fatalf("banner after recovery: %+v", b)
	}
}

// A replica restart (a new service on the same stored state) does not
// alert again for a condition that is already open.
func TestCheckDoesNotRepeatAfterRestart(t *testing.T) {
	f := newFixture(t)
	f.feeds.views = []feedstatus.View{kevView(t0.Add(-7 * time.Hour))}
	f.tick(t, 0)
	if f.n.Count() != 1 {
		t.Fatalf("first: %v", f.n.Subjects)
	}
	again := New(f.feeds, f.corpus, f.repo, logger.NewNop())
	again.SetClock(func() time.Time { return f.now })
	again.SetNotifier(f.n)
	f.now = f.now.Add(CheckEvery)
	if _, err := again.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.n.Count() != 1 {
		t.Fatalf("repeated after restart: %v", f.n.Subjects)
	}
}

// The corpus is read only when a bundle was applied (a fresh install with
// no corpus does not count CVEs).
func TestCheckSkipsCorpusWithoutBundle(t *testing.T) {
	f := newFixture(t)
	f.feeds.views = []feedstatus.View{kevView(t0)}
	f.tick(t, 0)
	if f.corpus.calls != 0 {
		t.Fatalf("corpus read without a bundle")
	}
}

// A watch that stopped running is itself shown: the banner reports unknown
// freshness rather than staying quiet.
func TestBannerWhenTheWatchStopped(t *testing.T) {
	f := newFixture(t)
	if b := f.banner(t); b.Stale {
		t.Fatalf("banner before the first check: %+v", b)
	}
	f.feeds.views = []feedstatus.View{bundleView(t0.Add(-time.Hour), t0)}
	f.tick(t, 0)
	f.now = f.now.Add(CheckStaleAfter + time.Minute)
	b := f.banner(t)
	if !b.Stale || !slices.Equal(b.Codes, []string{CodeCheckNotRunning}) {
		t.Fatalf("banner: %+v", b)
	}
}

// A feed status that cannot be read is an error for the controller (its
// error counter and logs), never an empty "all clear".
func TestCheckFeedReadError(t *testing.T) {
	f := newFixture(t)
	f.feeds.err = errors.New("db down")
	if _, err := f.svc.Check(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if f.n.Count() != 0 {
		t.Fatalf("mail: %v", f.n.Subjects)
	}
}
