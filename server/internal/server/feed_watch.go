package server

// Freshness watch (internal/app/feedwatch): alerts and the all-user banner
// when vulnerability data stops arriving, in direct and relay mode alike.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedwatch"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// newFeedWatch builds the watch (nil without the feeds or platform settings).
func newFeedWatch(repos *Repositories, s *Services, log *logger.Logger) *feedwatch.Service {
	if s.ThreatIntel == nil || repos.PlatformSetting == nil {
		return nil
	}
	var corpus feedwatch.Corpus
	if repos.CVECorpus != nil {
		corpus = corpusFreshness{repos.CVECorpus}
	}
	return feedwatch.New(s.ThreatIntel, corpus, repos.PlatformSetting, log.With("controller", "feed-freshness"))
}

// corpusFreshness adapts the corpus repository to the watch.
type corpusFreshness struct{ repo *postgres.CVECorpusRepository }

func (c corpusFreshness) FreshnessStats(ctx context.Context, now time.Time) (feedwatch.CorpusStats, error) {
	st, err := c.repo.FreshnessStats(ctx, now)
	if err != nil {
		return feedwatch.CorpusStats{}, err
	}
	return feedwatch.CorpusStats{NewestPublished: st.NewestPublished, Published24h: st.Published24h,
		PublishedPrior30d: st.PublishedPrior30d}, nil
}
