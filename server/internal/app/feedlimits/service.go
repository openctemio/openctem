// Package feedlimits is the console setting of how old the platform's
// vulnerability data may be before it counts as out of date (the stale
// limits of internal/app/feedstatus): the console card, the administrators'
// alert and every user's banner use it.
//
// The default (12 hours) suits a platform that receives the feed by itself
// (direct, proxy, mirror or relay). A site that copies releases by hand (an
// offline folder, VULNFEED_BUNDLE_DIR) may raise it, up to 7 days, so a
// copy every day or two does not show the banner. KEV rides the bundle and
// takes the same limit; EPSS takes it plus a day. A release older than
// 7 days is still refused by the importer, whatever the limit.
//
// Raising the limit hides out-of-date data for longer and loosens which
// release side data (KEV, EPSS) counts as current, so a change needs a super
// admin, a fresh step-up and a reason; it is a critical audit entry and
// every administrator is told.
//
// Design: docs/architecture/intelligence-feeds.md, "Freshness".
package feedlimits

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/internal/app/feedstatus"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "feed_freshness.limits"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.feed_freshness_limits_changed"

// Path is the console route of the setting.
const Path = "/api/v1/admin/settings/feed-freshness"

// Bounds of the bundle limit, in hours.
var (
	MinHours     = int(feedstatus.MinStaleAfterVulnfeed / time.Hour)
	MaxHours     = int(feedstatus.MaxStaleAfterVulnfeed / time.Hour)
	DefaultHours = int(feedstatus.StaleAfterVulnfeed / time.Hour)
)

// Sources of the limit in force.
const (
	SourceDefault = "default"
	SourceConsole = "console"
)

// Errors of the service.
var (
	ErrInvalid = fmt.Errorf("%w: the vulnerability data limit must be between %d and %d hours",
		shared.ErrValidation, MinHours, MaxHours)
	ErrNoActor = errors.New("a feed freshness change needs an administrator")
)

type stored struct {
	BundleHours int `json:"bundle_hours"`
}

// Settings is what an administrator sees.
type Settings struct {
	// BundleHours is the limit of the vulnerability bundle and KEV.
	BundleHours int
	// EPSSHours is the EPSS limit that follows from it.
	EPSSHours int
	Source    string
	Version   int
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Service reads and changes the limits.
type Service struct {
	store    *consolesetting.Store[stored]
	recorder *consolesetting.Recorder
	logger   *logger.Logger
}

// NewService creates the service. recorder may be nil (tests).
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder,
		logger: log.With("service", "feed_limits")}
}

func settingsOf(hours int) Settings {
	l := feedstatus.Limits{Vulnfeed: time.Duration(hours) * time.Hour}
	return Settings{BundleHours: int(l.Bundle() / time.Hour),
		EPSSHours: int(l.StaleAfter(feedstatus.SourceEPSS) / time.Hour), Source: SourceDefault}
}

// Get returns the limits in force and where they come from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	st, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if !m.Stored || st.BundleHours == 0 {
		return settingsOf(DefaultHours), nil
	}
	out := settingsOf(st.BundleHours)
	out.Source, out.Version, out.UpdatedAt, out.UpdatedBy = SourceConsole, m.Version, m.UpdatedAt, m.UpdatedBy
	return out, nil
}

// Limits are the limits in force for feedstatus. A setting that cannot be
// read gives the strictest limit (MinHours): never looser than what an
// administrator stored, so out-of-date data is reported sooner, never later.
func (s *Service) Limits(ctx context.Context) feedstatus.Limits {
	st, err := s.Get(ctx)
	if err != nil {
		s.logger.Warn("feed freshness limits not read; using the strictest limit", "error", err)
		return feedstatus.Limits{Vulnfeed: feedstatus.MinStaleAfterVulnfeed}
	}
	return feedstatus.Limits{Vulnfeed: time.Duration(st.BundleHours) * time.Hour}
}

// Update stores the bundle limit. The caller checked the super admin role
// and the fresh step-up. expectedVersion is the version read (0: nothing
// stored); reason is required.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, hours, expectedVersion int, reason, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if hours < MinHours || hours > MaxHours {
		return Settings{}, ErrInvalid
	}
	reason, err := consolesetting.CheckReason(reason)
	if err != nil {
		return Settings{}, err
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.store.Put(ctx, stored{BundleHours: hours}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	next := settingsOf(hours)
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Vulnerability data age limit",
		Method: "PUT", Path: Path, Reason: reason, Critical: true, Notify: true,
		Details: map[string]any{"previous_bundle_hours": prev.BundleHours, "previous_source": prev.Source,
			"bundle_hours": hours, "kev_hours": next.BundleHours, "epss_hours": next.EPSSHours},
	}, ip, userAgent)
	return s.Get(ctx)
}
