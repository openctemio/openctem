package main

// Feed relay (docs/rfcs/RFC-142-feed-relay.md): a platform with no outbound
// access receives its signed feeds through a designated platform sensor.

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/feedrelay"
	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	signerclient "github.com/openctemio/openctem/api/internal/infra/signer"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// newFeedRelayService builds the relay. Relay mode is locked off while a
// feed bundle directory is configured (that directory is the only origin)
// or when no job signer signs the rounds.
func newFeedRelayService(cfg *config.Config, db *sql.DB, repos *Repositories, s *Services, log *logger.Logger) *feedrelay.Service {
	if db == nil || repos.PlatformSetting == nil || repos.Sensor == nil {
		return nil
	}
	fc := feedrelay.Config{Spool: feedRelaySpool(cfg)}
	if cfg.Worker.VulnFeedBundleDir != "" {
		fc.Locked = "bundle_dir"
	}
	if sock := cfg.SensorConfig.SignerSocket; sock != "" {
		fc.Signer = signerclient.NewClient(sock, cfg.SensorConfig.SignerTimeout)
	}
	return feedrelay.NewService(fc, postgres.NewFeedRelayRoundRepository(&postgres.DB{DB: db}), repos.Sensor,
		repos.PlatformSetting, s.SettingRecorder, log)
}

// feedRelaySpool is FEED_RELAY_DIR, default <FEED_CACHE_DIR>/relay. Every
// API replica must see the same directory (the importer runs on one replica,
// uploads arrive on any).
func feedRelaySpool(cfg *config.Config) string {
	if d := strings.TrimSpace(cfg.Worker.FeedRelayDir); d != "" {
		return d
	}
	return filepath.Join(cfg.Scope.FeedCacheDir, "relay")
}

// registerRelayFeeds adds the feeds the relay serves: the vulnerability
// feed (with its side files) and the version check's release feed.
func registerRelayFeeds(cfg *config.Config, svc *Services, im *vulnfeed.Importer) {
	r := svc.FeedRelay
	if r == nil {
		return
	}
	if im != nil {
		urls := append([]string{strings.TrimRight(cfg.Worker.VulnFeedBaseURL, "/") + "/latest/download"}, cfg.Worker.VulnFeedMirrors...)
		r.AddFeed(&feedrelay.VulnFeed{Importer: im, URLs: urls})
	}
	if svc.VersionCheck != nil && svc.VersionCheck.Configured() {
		r.AddFeed(&feedrelay.VersionCheck{Service: svc.VersionCheck, URL: cfg.Worker.VersionCheckURL})
	}
}

// relayMode is the gate of the feed fetchers (nil service: never).
func relayMode(svc *Services) func(ctx context.Context) bool {
	if svc == nil || svc.FeedRelay == nil {
		return func(context.Context) bool { return false }
	}
	return svc.FeedRelay.RelayMode
}

// feedrelayVulnFeed is the relay feed name of the vulnerability feed.
const feedrelayVulnFeed = "vulnfeed"

// newFeedRelayHandler serves the relay routes (nil without the service).
func newFeedRelayHandler(svc *Services, log *logger.Logger) *handler.FeedRelayHandler {
	if svc == nil || svc.FeedRelay == nil {
		return nil
	}
	return handler.NewFeedRelayHandler(svc.FeedRelay, log)
}
