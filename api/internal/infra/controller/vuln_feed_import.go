package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// VulnFeedImportController imports the newest signed vulnerability bundle
// (RFC-066 §5.5) and warns when the corpus goes stale.
type VulnFeedImportController struct {
	importer *vulnfeed.Importer
	events   CorpusEventEmitter
	logger   *logger.Logger
}

// CorpusEventEmitter reports the material changes of the corpus after an
// import (*vulnevent.Emitter, docs/rfcs/RFC-117-emerging-threat-alerts.md).
type CorpusEventEmitter interface {
	EmitCorpus(ctx context.Context) (int, error)
	Prune(ctx context.Context) (int64, error)
}

// SetEventEmitter wires the vulnerability event log (nil: no events).
func (c *VulnFeedImportController) SetEventEmitter(e CorpusEventEmitter) { c.events = e }

// NewVulnFeedImportController creates the controller.
func NewVulnFeedImportController(im *vulnfeed.Importer, log *logger.Logger) *VulnFeedImportController {
	return &VulnFeedImportController{importer: im, logger: log}
}

// Name returns the controller name.
func (c *VulnFeedImportController) Name() string { return "vuln-feed-import" }

// Interval: every 20 minutes. A bundle is published every hour; a run with
// nothing newer fetches only the key set and the pointer, and a platform
// that applied the previous bundle fetches only the delta.
func (c *VulnFeedImportController) Interval() time.Duration { return 20 * time.Minute }

// ReconcileTimeout leaves room for a first snapshot.
func (c *VulnFeedImportController) ReconcileTimeout() time.Duration { return 45 * time.Minute }

// Exclusive: one replica imports.
func (c *VulnFeedImportController) Exclusive() bool { return true }

// Reconcile imports and checks staleness.
func (c *VulnFeedImportController) Reconcile(ctx context.Context) (int, error) {
	res, err := c.importer.Run(ctx)
	if err != nil {
		c.logger.Warn("vulnerability bundle not imported", "error", err)
	}
	if stale, serr := c.importer.CheckStale(ctx); serr == nil && stale && err == nil && !res.Ran {
		c.logger.Warn("vulnerability corpus is stale: no new bundle for more than three days")
	}
	// After the import, in the same run: the emitter reads the records the
	// import wrote (also those of a run that failed half way) by their
	// sync time, and nothing else writes the corpus meanwhile.
	if c.events != nil {
		if _, eerr := c.events.EmitCorpus(ctx); eerr != nil {
			c.logger.Warn("vulnerability events not emitted", "source", "corpus", "error", eerr)
		}
		if _, perr := c.events.Prune(ctx); perr != nil {
			c.logger.Warn("vulnerability events not pruned", "error", perr)
		}
	}
	return res.CVEs, nil
}
