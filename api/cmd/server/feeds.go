package main

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/api/internal/app/feedstatus"
	"github.com/openctemio/openctem/api/internal/app/feedsync"
	vulneventapp "github.com/openctemio/openctem/api/internal/app/vulnevent"
	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// feedControllers are the controllers of the platform-wide intelligence feeds:
// the daily EPSS refresh, the hourly KEV refresh and the vulnerability bundle
// import. The scheduler runs one set; the admin "Sync now" runs another set
// in the background (the feed's status row serializes the two).
type feedControllers struct {
	epss, kev *controller.ThreatIntelRefreshController
	// bundles is nil when the bundle import cannot be built.
	bundles *controller.VulnFeedImportController
	// importer is the bundle importer (nil: not configured).
	importer *vulnfeed.Importer
	// bundlesConfigured: VULNFEED_ROOT_KEY_ID is set.
	bundlesConfigured bool
}

// newFeedControllers builds them. Each recomputes the priority of only the
// findings whose CVE intel moved and reports material changes to the
// vulnerability event log (RFC-117).
func newFeedControllers(cfg *config.Config, svc *Services, repos *Repositories, log *logger.Logger) feedControllers {
	var intelQueue controller.IntelChangeQueue
	if svc.Scoring != nil {
		intelQueue = svc.Scoring
	}
	var vulnEvents *vulneventapp.Emitter
	if repos.VulnEvent != nil {
		vulnEvents = vulneventapp.NewEmitter(repos.VulnEvent, log)
	}
	f := feedControllers{
		epss:              controller.NewThreatIntelRefreshController(svc.ThreatIntel, intelQueue, log.With("controller", "threat-intel-refresh")),
		kev:               controller.NewKEVRefreshController(svc.ThreatIntel, repos.KEVEscalator, intelQueue, log.With("controller", "kev-refresh")),
		bundlesConfigured: cfg.Worker.VulnFeedRootKeyID != "",
	}
	if vulnEvents != nil {
		f.epss.SetEventEmitter(vulnEvents)
		f.kev.SetEventEmitter(vulnEvents)
	}
	if repos.ThreatIntel != nil && repos.CVECorpus != nil && repos.Software != nil {
		im, err := newVulnFeedImporter(cfg, repos, log.With("component", "vulnfeed"))
		if err != nil {
			log.Error("vulnerability bundle import disabled", "error", err)
			return f
		}
		// Relay mode (RFC-142): the relay spool is the only origin.
		if svc.FeedRelay != nil {
			im.WithRelay(svc.FeedRelay.SpoolIfRelay(feedrelayVulnFeed))
		}
		f.importer = im
		// KEV and EPSS ride the same release as a signed side manifest: applied
		// when newer than what the platform holds, then the same findings sweep
		// and event log as after a direct sync.
		if svc.ThreatIntel != nil {
			im.WithIntel(svc.ThreatIntel)
			svc.ThreatIntel.SetAfterBundleApply(func(ctx context.Context, source string) {
				switch source {
				case "kev":
					f.kev.Sweeper().Run(ctx, "kev", true, true)
				case "epss":
					f.epss.Sweeper().Run(ctx, "epss", true, true)
				}
			})
		}
		f.bundles = controller.NewVulnFeedImportController(im, log.With("controller", "vuln-feed-import"))
		if vulnEvents != nil {
			f.bundles.SetEventEmitter(vulnEvents)
		}
	}
	return f
}

// newFeedRunner builds the background runner of the admin "Sync now": one job
// per feed, the same pass the feed's controller runs on schedule.
func newFeedRunner(deps *HandlerDeps, log *logger.Logger) (*feedsync.Runner, bool) {
	if deps.Services == nil || deps.Services.ThreatIntel == nil || deps.Repos == nil {
		return nil, false
	}
	f := newFeedControllers(deps.Config, deps.Services, deps.Repos, log)
	pass := func(c interface {
		Reconcile(ctx context.Context) (int, error)
	}) feedsync.Job {
		return func(ctx context.Context) error { _, err := c.Reconcile(ctx); return err }
	}
	jobs := map[string]feedsync.Job{
		feedstatus.SourceEPSS: pass(f.epss),
		feedstatus.SourceKEV:  pass(f.kev),
	}
	if f.bundles != nil {
		jobs[feedstatus.SourceVulnfeed] = pass(f.bundles)
	}
	return feedsync.New(jobs, log), f.bundlesConfigured
}

// newVulnFeedImporter builds the vulnerability bundle importer. The import
// controller and the admin "Sync now" endpoint each use one: chunked (v2)
// bundles are fetched with retries, resume and mirror fall-back and applied
// chunk by chunk with a durable checkpoint (docs/architecture/feed-transfer.md);
// v1 stays the fallback.
func newVulnFeedImporter(cfg *config.Config, repos *Repositories, log *logger.Logger) (*vulnfeed.Importer, error) {
	im, err := vulnfeed.NewImporter(vulnfeed.Config{
		RootKeyID: cfg.Worker.VulnFeedRootKeyID, BaseURL: cfg.Worker.VulnFeedBaseURL, BundleDir: cfg.Worker.VulnFeedBundleDir,
	}, repos.CVECorpus, repos.ThreatIntel.SyncStatus(), repos.Software, log)
	if err != nil {
		return nil, err
	}
	im.WithChunks(repos.CVECorpus, vulnfeed.Transfer{Mirrors: cfg.Worker.VulnFeedMirrors, CacheDir: cfg.Scope.FeedCacheDir,
		Client: httpsec.SafeHTTPClient(0), Registerer: prometheus.DefaultRegisterer})
	return im, nil
}
