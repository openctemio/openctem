// Package vulnfeedsources is the platform setting vulnfeed.sources: where
// the signed vulnerability feed is fetched from, the release base URL and
// the mirrors tried after it in direct mode. The relay sensors fetch the
// same release base URL in relay mode (the mirrors are direct mode only).
//
// The environment is the default (VULNFEED_BASE_URL, VULNFEED_MIRRORS) and
// pins the value when either variable is set: the console then shows it
// locked and refuses a change, as for the other settings that moved from
// the environment. While neither is set, a super admin may change it with a
// fresh step-up and a reason; the change is audited as critical, with the
// old and new values, and every administrator is told.
//
// What the console never changes: the pinned root key id
// (VULNFEED_ROOT_KEY_ID, a trust anchor) and the bundle directory
// (VULNFEED_BUNDLE_DIR, a server path). A new origin adds no trust: every
// file from any origin is verified against the pinned root before anything
// is applied, so a wrong origin can only stop the feed, never feed it.
//
// Design: docs/rfcs/RFC-079-console-platform-settings.md;
// docs/architecture/feed-transfer.md ("Feed sources in the console").
package vulnfeedsources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/internal/app/consolesetting"
	"github.com/openctemio/openctem/server/internal/app/vulnfeed"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SettingKey is the platform_settings key.
const SettingKey = "vulnfeed.sources"

// ActionChanged is the admin audit action of a change.
const ActionChanged = "platform.vulnfeed_sources_changed"

// Environment variables that set (and pin) the value.
const (
	EnvBaseURL = "VULNFEED_BASE_URL"
	EnvMirrors = "VULNFEED_MIRRORS"
)

// MaxMirrors bounds the mirror list.
const MaxMirrors = 5

// Sources of the value in force.
const (
	SourceDefault     = "default"
	SourceEnvironment = "environment"
	SourceConsole     = "console"
)

// Errors.
var (
	ErrLockedByEnvironment = errors.New("the vulnerability feed address is set by the server configuration (VULNFEED_BASE_URL or VULNFEED_MIRRORS)")
	ErrBundleDir           = errors.New("the server reads the vulnerability feed from a local bundle directory, so it fetches nothing over the network")
	ErrRelayMode           = errors.New("feeds come through the relay sensors, so the platform makes no outbound request; the relay uses the saved address at its next cycle")
	ErrNotConfigured       = errors.New("the vulnerability feed import is not available on this server")
	ErrNoActor             = errors.New("a feed address change needs an administrator")
)

type stored struct {
	BaseURL string   `json:"base_url"`
	Mirrors []string `json:"mirrors"`
}

// Env is the server configuration the setting reads.
type Env struct {
	// BaseURL and Mirrors are the values in force from the environment
	// (BaseURL already holds the built-in default when the variable is
	// unset).
	BaseURL string
	Mirrors []string
	// Pinned: VULNFEED_BASE_URL or VULNFEED_MIRRORS is set.
	Pinned bool
	// RootKeyID is the pinned root (VULNFEED_ROOT_KEY_ID or the official one).
	RootKeyID string
	// OfficialRootKeyID is the root of the official feed.
	OfficialRootKeyID string
	// BundleDirSet: VULNFEED_BUNDLE_DIR is set (its path is never shown).
	BundleDirSet bool
}

// Settings is what an administrator sees.
type Settings struct {
	BaseURL             string
	Mirrors             []string
	DefaultBaseURL      string
	DefaultMirrors      []string
	Source              string
	LockedByEnvironment bool
	// RootOfficial: the pinned root is the official feed's.
	RootOfficial bool
	RootKeyID    string
	BundleDirSet bool
	Version      int
	UpdatedAt    time.Time
	UpdatedBy    *shared.ID
}

// Prober tests origins without importing (*vulnfeed.Importer).
type Prober interface {
	Probe(ctx context.Context, base string, mirrors []string) []vulnfeed.ProbeResult
}

// Service answers the sources in force and changes them.
type Service struct {
	store     *consolesetting.Store[stored]
	recorder  *consolesetting.Recorder
	env       Env
	prober    Prober
	relayMode func(ctx context.Context) bool
	log       *logger.Logger
}

// NewService creates the service.
func NewService(repo platformsetting.Repository, recorder *consolesetting.Recorder, env Env, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	env.BaseURL = strings.TrimRight(strings.TrimSpace(env.BaseURL), "/")
	if env.BaseURL == "" {
		env.BaseURL = vulnfeed.DefaultBaseURL
	}
	return &Service{store: consolesetting.NewStore[stored](repo, SettingKey), recorder: recorder, env: env,
		log: log.With("service", "vulnfeed_sources")}
}

// SetProber wires the test fetch.
func (s *Service) SetProber(p Prober) { s.prober = p }

// SetRelayMode wires the feed delivery mode (relay: the platform makes no
// outbound request, so the test fetch is refused).
func (s *Service) SetRelayMode(f func(ctx context.Context) bool) { s.relayMode = f }

// Get returns the sources in force and where they come from.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	out := Settings{BaseURL: s.env.BaseURL, Mirrors: clone(s.env.Mirrors), DefaultBaseURL: s.env.BaseURL,
		DefaultMirrors: clone(s.env.Mirrors), Source: SourceDefault, RootKeyID: s.env.RootKeyID,
		RootOfficial: s.env.RootKeyID != "" && s.env.RootKeyID == s.env.OfficialRootKeyID, BundleDirSet: s.env.BundleDirSet}
	if s.env.Pinned {
		out.Source, out.LockedByEnvironment = SourceEnvironment, true
		return out, nil
	}
	v, m, err := s.store.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if m.Stored {
		out.BaseURL, out.Mirrors, out.Source = v.BaseURL, clone(v.Mirrors), SourceConsole
		out.Version, out.UpdatedAt, out.UpdatedBy = m.Version, m.UpdatedAt, m.UpdatedBy
	}
	return out, nil
}

// FeedSources implements vulnfeed.Sources. A stored value that cannot be
// read or no longer validates falls back to the environment (logged): the
// server's own configuration is always a safe origin.
func (s *Service) FeedSources(ctx context.Context) (string, []string) {
	v, err := s.Get(ctx)
	if err != nil {
		s.log.Warn("vulnfeed.sources unreadable; using the server configuration", "error", err)
		return s.env.BaseURL, clone(s.env.Mirrors)
	}
	if v.Source == SourceConsole {
		if _, _, err := Normalize(v.BaseURL, v.Mirrors); err != nil {
			s.log.Warn("vulnfeed.sources no longer valid; using the server configuration", "error", err)
			return s.env.BaseURL, clone(s.env.Mirrors)
		}
	}
	return v.BaseURL, v.Mirrors
}

// RelayOrigin is the origin the relay sensors fetch the feed from: the
// release base URL in force + /latest/download. The job signer still
// refuses an origin outside SIGNER_FEED_ORIGINS.
func (s *Service) RelayOrigin() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base, _ := s.FeedSources(ctx)
	return strings.TrimRight(base, "/") + "/latest/download"
}

// Normalize trims and validates a base URL and its mirrors: https only, no
// credentials, query or fragment, not an internal address, at most
// MaxMirrors mirrors, no duplicates.
func Normalize(base string, mirrors []string) (string, []string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if err := vulnfeed.ValidateOrigin(base); err != nil {
		return "", nil, fmt.Errorf("%w: the release URL %s", shared.ErrValidation, originReason(err))
	}
	if len(mirrors) > MaxMirrors {
		return "", nil, fmt.Errorf("%w: at most %d mirrors", shared.ErrValidation, MaxMirrors)
	}
	out := make([]string, 0, len(mirrors))
	seen := map[string]bool{strings.ToLower(base): true}
	for i, m := range mirrors {
		m = strings.TrimRight(strings.TrimSpace(m), "/")
		if m == "" {
			continue
		}
		if err := vulnfeed.ValidateOrigin(m); err != nil {
			return "", nil, fmt.Errorf("%w: mirror %d %s", shared.ErrValidation, i+1, originReason(err))
		}
		if seen[strings.ToLower(m)] {
			return "", nil, fmt.Errorf("%w: mirror %d is listed twice", shared.ErrValidation, i+1)
		}
		seen[strings.ToLower(m)] = true
		out = append(out, m)
	}
	return base, out, nil
}

// Input is a change.
type Input struct {
	BaseURL string
	Mirrors []string
	Reason  string
	// Version is the version read (0: nothing stored).
	Version int
}

// Update stores the sources. The caller checked the permission and the
// fresh step-up.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, in Input, ip, userAgent string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if s.env.Pinned {
		return Settings{}, ErrLockedByEnvironment
	}
	base, mirrors, err := Normalize(in.BaseURL, in.Mirrors)
	if err != nil {
		return Settings{}, err
	}
	reason, err := consolesetting.CheckReason(in.Reason)
	if err != nil {
		return Settings{}, err
	}
	prev, err := s.Get(ctx)
	if err != nil {
		// A broken stored value must still be replaceable.
		prev = Settings{Source: "unreadable"}
	}
	if _, err := s.store.Put(ctx, stored{BaseURL: base, Mirrors: mirrors}, in.Version, actor.ID()); err != nil {
		return Settings{}, err
	}
	s.recorder.Record(ctx, actor, consolesetting.Change{
		Action: ActionChanged, Key: SettingKey, Title: "Vulnerability feed address",
		Method: "PUT", Path: "/api/v1/admin/settings/vulnfeed-sources", Reason: reason, Critical: true, Notify: true,
		// Full addresses: a feed address can carry no credential (no user
		// information, query or fragment is accepted), so the audit keeps
		// the path too; "release" is not a *_url key, which the audit
		// reduces to its origin.
		Details: map[string]any{
			"previous_release": prev.BaseURL, "previous_mirrors": nonNil(prev.Mirrors), "previous_source": prev.Source,
			"release": base, "mirrors": mirrors,
		},
	}, ip, userAgent)
	return s.Get(ctx)
}

// Test fetches the newest signed pointer from base and each mirror (the
// values in force when base is empty) and verifies it against the pinned
// root, without importing anything. Refused in relay mode and with a bundle
// directory: the platform then makes no outbound request.
func (s *Service) Test(ctx context.Context, base string, mirrors []string) ([]vulnfeed.ProbeResult, error) {
	if s.prober == nil || s.env.RootKeyID == "" {
		return nil, ErrNotConfigured
	}
	if s.env.BundleDirSet {
		return nil, ErrBundleDir
	}
	if s.relayMode != nil && s.relayMode(ctx) {
		return nil, ErrRelayMode
	}
	if strings.TrimSpace(base) == "" {
		base, mirrors = s.FeedSources(ctx)
	}
	base, mirrors, err := Normalize(base, mirrors)
	if err != nil {
		return nil, err
	}
	return s.prober.Probe(ctx, base, mirrors), nil
}

// originReason is the fixed text of a ValidateOrigin refusal.
func originReason(err error) string {
	switch {
	case errors.Is(err, vulnfeed.ErrOriginLength):
		return vulnfeed.ErrOriginLength.Error()
	case errors.Is(err, vulnfeed.ErrOriginInternal):
		return vulnfeed.ErrOriginInternal.Error()
	default:
		return vulnfeed.ErrOriginNotHTTPS.Error()
	}
}

func clone(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

func nonNil(v []string) []string { return clone(v) }
