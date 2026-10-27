package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// ThreatIntelRefreshController periodically refreshes one threat intel feed.
// The EPSS refresh runs daily (FIRST publishes once a day); the KEV refresh
// runs hourly with a conditional request, so a CISA addition reaches
// findings and emerging-threat alerts within the hour. After a sync it
// queues a priority recompute for only the open findings whose CVE changed
// (an EPSS threshold crossed, KEV membership changed), never a whole
// tenant; the KEV refresh then reconciles the is_in_kev flag of findings with
// the catalog. Both report material changes to the vulnerability event log.
type ThreatIntelRefreshController struct {
	service *threat.IntelService
	feed    string
	logger  *logger.Logger
	// sweeper does the work after the feed changed, whichever path
	// delivered it (see IntelSweeper).
	sweeper *IntelSweeper
}

// NewThreatIntelRefreshController creates the daily EPSS refresh. queue may
// be nil.
func NewThreatIntelRefreshController(service *threat.IntelService, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, feed: intelFeedEPSS, logger: log,
		sweeper: NewIntelSweeper(nil, queue, log)}
}

// NewKEVRefreshController creates the hourly KEV refresh. queue may be nil.
func NewKEVRefreshController(service *threat.IntelService, escalator threat.KEVEscalator, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, feed: intelFeedKEV, logger: log,
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
		return time.Hour
	}
	return 24 * time.Hour
}

// Reconcile fetches and persists the feed, queues the findings whose intel
// moved, reconciles KEV flags and reports material changes.
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	var r threat.IntelSyncResult
	// The signed release carries the feed too: the direct fetch is the
	// supplier or a fallback depending on the platform setting.
	if d := c.service.ShouldFetchDirect(ctx, c.feed); !d.Run {
		r = threat.IntelSyncResult{Source: c.feed, Skipped: true, SkipReason: d.Reason}
	} else if c.feed == intelFeedKEV {
		r = c.service.SyncKEV(ctx)
	} else {
		r = c.service.SyncEPSS(ctx)
	}
	processed := 0
	switch {
	case r.Skipped:
		c.logger.Debug("threat intel direct fetch not needed", "source", r.Source, "reason", r.SkipReason)
	case r.Error != nil:
		c.logger.Warn("threat intel sync failed", "source", r.Source, "error", r.Error)
	case r.NotModified:
		c.logger.Debug("threat intel unchanged", "source", r.Source)
	default:
		processed += r.RecordsSynced
		c.logger.Info("threat intel synced", "source", r.Source, "records", r.RecordsSynced, "duration_ms", r.DurationMs)
	}
	processed += c.sweeper.Run(ctx, c.feed, r.Error == nil && !r.NotModified && !r.Skipped, r.Error == nil)

	return processed, nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *ThreatIntelRefreshController) Exclusive() bool { return true }
