package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/internal/app/threat"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// IntelChangeQueue queues the assets of open findings whose threat intel
// moved in a way a scoring model can see (docs/architecture/scoring-versions.md,
// "Intel updates"). Implemented by postgres.ScoringRepository.
type IntelChangeQueue interface {
	EnqueueIntelChanges(ctx context.Context) (int64, error)
	// RefreshFindingEPSS writes the catalog EPSS score onto
	// every open finding whose CVE's score changed (tenant by tenant, in
	// batches), so readers of the stored value (the CI gate's
	// epss_threshold) see today's score.
	RefreshFindingEPSS(ctx context.Context) (int64, error)
}

// IntelEventEmitter reports the material KEV and EPSS changes after a sync
// (*vulnevent.Emitter, docs/rfcs/RFC-117-emerging-threat-alerts.md).
type IntelEventEmitter interface {
	EmitKEV(ctx context.Context) (int, error)
	EmitEPSS(ctx context.Context) (int, error)
}

// Which feed a refresh controller syncs.
const (
	intelFeedEPSS = "epss"
	intelFeedKEV  = "kev"
)

// ThreatIntelRefreshController is the periodic pass of one threat intel feed
// (KEV hourly, EPSS daily). It fetches nothing: KEV and EPSS arrive only in
// the signed vulnerability release, and the bundle importer runs the same
// sweep right after it applied one (Sweeper). This pass compares open
// findings with the catalogs at least daily, so findings created since the
// last change (or a sweep that failed) are still reconciled, and reports
// material changes to the vulnerability event log.
type ThreatIntelRefreshController struct {
	feed   string
	logger *logger.Logger
	// sweeper does the work after the feed changed, whichever path
	// delivered it (see IntelSweeper).
	sweeper *IntelSweeper
}

// NewThreatIntelRefreshController creates the daily EPSS pass. queue may be
// nil.
func NewThreatIntelRefreshController(queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{feed: intelFeedEPSS, logger: log,
		sweeper: NewIntelSweeper(nil, queue, log)}
}

// NewKEVRefreshController creates the hourly KEV pass. queue may be nil.
func NewKEVRefreshController(escalator threat.KEVEscalator, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{feed: intelFeedKEV, logger: log,
		sweeper: NewIntelSweeper(escalator, queue, log)}
}

// SetEventEmitter wires the vulnerability event log (nil: no events).
func (c *ThreatIntelRefreshController) SetEventEmitter(e IntelEventEmitter) {
	c.sweeper.SetEventEmitter(e)
}

// Sweeper is the post-sync work of this feed, for the importer to run after
// it applied the same feed from a signed release.
func (c *ThreatIntelRefreshController) Sweeper() *IntelSweeper { return c.sweeper }

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string {
	if c.feed == intelFeedKEV {
		return "kev-refresh"
	}
	return "threat-intel-refresh"
}

// Interval: hourly for KEV, daily for EPSS.
func (c *ThreatIntelRefreshController) Interval() time.Duration {
	if c.feed == intelFeedKEV {
		return feedstatus.IntervalKEV
	}
	return feedstatus.IntervalEPSS
}

// Reconcile runs the sweep (the comparison of open findings with the
// catalogs when it is due, and the event log).
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	return c.sweeper.Run(ctx, c.feed, false, true), nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *ThreatIntelRefreshController) Exclusive() bool { return true }
