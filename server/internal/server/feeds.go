package server

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/internal/app/feedsync"
	vulneventapp "github.com/openctemio/openctem/server/internal/app/vulnevent"
	"github.com/openctemio/openctem/server/internal/app/vulnfeed"
	"github.com/openctemio/openctem/server/internal/app/vulnfeedsources"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/controller"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// feedControllers are the controllers of the platform-wide intelligence feeds:
// the vulnerability bundle import (which also carries KEV and EPSS: the
// platform fetches neither itself) and the daily and hourly passes that
// compare open findings with the KEV and EPSS catalogs. The scheduler runs
// one set; the admin "Sync now" runs another set in the background (the
// feed's status row serializes the two).
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
		epss:              controller.NewThreatIntelRefreshController(intelQueue, log.With("controller", "threat-intel-refresh")),
		kev:               controller.NewKEVRefreshController(repos.KEVEscalator, intelQueue, log.With("controller", "kev-refresh")),
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
		// The console setting of the feed address applies at every run.
		if svc.VulnFeedSources != nil {
			im.WithSources(svc.VulnFeedSources)
		}
		// Relay mode (RFC-142): the relay working directory is the only origin.
		if svc.FeedRelay != nil {
			im.WithRelay(svc.FeedRelay.DirIfRelay(feedrelayVulnFeed))
		}
		f.importer = im
		// Advisory cards ride the same side manifest (the cards stream).
		if repos.AdvisoryCards != nil {
			im.WithCards(repos.AdvisoryCards)
		}
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
	// KEV and EPSS ride the vulnerability release: "Sync now" for either
	// imports the newest release.
	jobs := map[string]feedsync.Job{}
	if f.bundles != nil {
		jobs[feedstatus.SourceVulnfeed] = pass(f.bundles)
		jobs[feedstatus.SourceKEV] = pass(f.bundles)
		jobs[feedstatus.SourceEPSS] = pass(f.bundles)
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
		Client: httpsec.FeedHTTPClient(0), Registerer: prometheus.DefaultRegisterer})
	return im, nil
}

// initVulnFeedSources builds the console setting of the vulnerability feed
// address (release base URL and mirrors; the environment is the default and
// pins it when set). Its test fetch uses an importer of its own that only
// probes: it never imports.
func (s *Services) initVulnFeedSources(cfg *config.Config, repos *Repositories, log *logger.Logger) {
	if repos.PlatformSetting == nil {
		return
	}
	s.VulnFeedSources = vulnfeedsources.NewService(repos.PlatformSetting, s.SettingRecorder, vulnfeedsources.Env{
		BaseURL: cfg.Worker.VulnFeedBaseURL, Mirrors: cfg.Worker.VulnFeedMirrors, Pinned: cfg.Worker.VulnFeedSourcesPinned,
		RootKeyID: cfg.Worker.VulnFeedRootKeyID, OfficialRootKeyID: config.VulnFeedOfficialRootKeyID,
		BundleDirSet: cfg.Worker.VulnFeedBundleDir != "",
	}, log)
	// Relay mode is read at the time of a test (the relay service is built
	// later; nil: direct).
	s.VulnFeedSources.SetRelayMode(func(ctx context.Context) bool {
		return s.FeedRelay != nil && s.FeedRelay.RelayMode(ctx)
	})
	if repos.ThreatIntel != nil && repos.CVECorpus != nil && repos.Software != nil {
		if im, err := newVulnFeedImporter(cfg, repos, log.With("component", "vulnfeed_probe")); err == nil {
			s.VulnFeedSources.SetProber(im)
		}
	}
}
