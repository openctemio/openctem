package feedrelay

import (
	"context"
	"slices"
	"testing"
	"time"

	dom "github.com/openctemio/openctem/server/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The relay round of the vulnerability feed names the release origin in
// force when the round is created (the console setting of the feed address),
// and that is the origin the job signer is asked to sign: a console change
// reaches the next round without a restart. Without an Origin the
// configured URLs are used.
func TestVulnFeedRoundUsesTheOriginInForce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	origin := "https://feed.example.org/releases/latest/download"
	vf := &VulnFeed{URLs: []string{"https://github.com/openctemio/vulnfeed-bundles/releases/latest/download"},
		Origin: func() string { return origin }}
	f.svc = NewService(Config{WorkDir: t.TempDir(), Signer: f.signer, Now: func() time.Time { return f.now }}, f.store, f.store, f.sensors, f.settings, nil, logger.NewNop())
	f.svc.AddFeed(originFeed{VulnFeed: vf, fake: f.feed})
	f.relayOn(t)
	f.tick(t)
	rd, err := f.store.Latest(ctx, dom.FeedVulnFeed)
	if err != nil || rd == nil || !slices.Equal(rd.Origins, []string{origin}) {
		t.Fatalf("round origins %+v (%v)", rd, err)
	}
	if n, _, err := f.svc.Next(ctx, f.relay); err != nil || n == nil {
		t.Fatalf("next: %v %v", n, err)
	}
	if len(f.signer.got) != 1 || !slices.Equal(f.signer.got[0].Targets, []string{origin}) {
		t.Fatalf("signed targets %+v", f.signer.got)
	}

	origin = "https://mirror.example.net/vulnfeed/latest/download"
	if got := vf.Origins(); !slices.Equal(got, []string{origin}) {
		t.Fatalf("after a change: %v", got)
	}
	// An origin that is not an https origin is dropped (the signer and the
	// sensor refuse it anyway); no Origin: the configured URLs.
	origin = "http://plain.example.org/x"
	if got := vf.Origins(); len(got) != 0 {
		t.Fatalf("http origin kept: %v", got)
	}
	vf.Origin = nil
	if got := vf.Origins(); !slices.Equal(got, vf.URLs) {
		t.Fatalf("configured URLs: %v", got)
	}
}

// originFeed is the real VulnFeed's naming of origins and head, with the
// fake's plan, import and freshness (no importer).
type originFeed struct {
	*VulnFeed
	fake *fakeFeed
}

func (o originFeed) Plan(ctx context.Context, dir string) (Plan, error) { return o.fake.Plan(ctx, dir) }
func (o originFeed) Import(ctx context.Context, dir string) ([]string, error) {
	return o.fake.Import(ctx, dir)
}
func (o originFeed) Freshness(ctx context.Context) (Freshness, error) { return o.fake.Freshness(ctx) }
