// Package versioncheck tells platform administrators about newer releases and
// security releases of OpenCTEM: it fetches the signed release feed once a
// day (or takes an administrator's offline import of it), verifies it with a
// root pinned in the binary, and compares it with the running version on the
// instance. The request carries no instance id, no version and no counts.
// Design: docs/rfcs/RFC-105-version-check-and-usage-telemetry.md.
package versioncheck

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

// Origins of the applied feed.
const (
	OriginOnline = "online"
	OriginImport = "import"
)

// Error codes stored and shown in the console (never raw upstream text).
const (
	ErrCodeUnreachable = "unreachable"
	ErrCodeHTTPStatus  = "http_status"
	// ErrCodeNotPublished: the feed URL answered 404 (the release has no
	// feed asset: the publisher has no signing key yet, or a mirror lacks it).
	ErrCodeNotPublished = "not_published"
	ErrCodeTooLarge     = "too_large"
	ErrCodeInvalid      = "invalid"
	ErrCodeRollback     = "rollback"
	ErrCodeConflict     = "conflict"
	ErrCodeExpired      = "expired"
	ErrCodeNoKey        = "no_key"
)

// Schedule.
const (
	// DefaultURL is the latest release's feed asset.
	DefaultURL       = "https://github.com/openctemio/openctem/releases/latest/download/" + releasefeed.FileName
	UserAgent        = "openctem-version-check/1"
	CheckInterval    = 24 * time.Hour
	CheckJitter      = 4 * time.Hour
	OfflineInterval  = 7 * 24 * time.Hour
	OfflineAfter     = 3
	FirstCheckMin    = 5 * time.Minute
	FirstCheckSpread = 55 * time.Minute
	FetchTimeout     = 30 * time.Second
	MaxRedirects     = 3
)

// State is the stored state of the instance's version check.
type State struct {
	Feed                *releasefeed.Feed
	FeedDigest          string
	Origin              string
	AppliedSequence     uint64
	AppliedAt           *time.Time
	LastAttemptAt       *time.Time
	LastError           string
	ConsecutiveFailures int
	NextCheckAt         *time.Time
}

// Repository stores the one state row.
type Repository interface {
	// Get returns the state; a zero State when no row exists yet.
	Get(ctx context.Context) (State, error)
	// ClaimDue creates the row (next check at first) when absent, then, when
	// the next check is due at now, moves it to next and reports true. Only
	// one replica wins a due check.
	ClaimDue(ctx context.Context, now, first, next time.Time) (bool, error)
	// Apply stores a verified feed unless a newer one, or another feed with
	// the same sequence, is already stored (reports false then), and clears
	// the failure count.
	Apply(ctx context.Context, v *releasefeed.Verified, origin string, now time.Time) (bool, error)
	// RecordFailure stores a failed online check and the next check time,
	// and returns the consecutive failure count.
	RecordFailure(ctx context.Context, code string, now time.Time, next func(failures int) time.Time) (int, error)
}

// Config configures the service.
type Config struct {
	// Enabled turns the daily online check on (VERSION_CHECK_ENABLED).
	// Offline import and the console view work either way.
	Enabled bool
	// URL is the feed location (VERSION_CHECK_URL, https; validated by the
	// configuration).
	URL string
	// Keys are the pinned feed keys (releasefeed.PinnedKeys in production).
	Keys []string
	// Running is the running version.
	Running string
	// OnFeed receives the applied feed (nil when none) whenever the
	// service loads it: at Refresh and after an online check or an import
	// stores one. The server uses it to learn the first-party component
	// releases (internal/versions.SetLearned). Optional.
	OnFeed func(*releasefeed.Feed)
	// Client fetches the feed; nil: the SSRF-guarded client.
	Client *http.Client
	// Now and Jitter are for tests.
	Now    func() time.Time
	Jitter func(max time.Duration) time.Duration
}

// Service is the version check.
type Service struct {
	repo   Repository
	cfg    Config
	logger *logger.Logger
	// settings holds the console switch (setting.go); nil: the environment
	// alone decides.
	settings platformsetting.Repository
}

// New creates the service.
func New(repo Repository, cfg Config, log *logger.Logger) *Service {
	if cfg.URL == "" {
		cfg.URL = DefaultURL
	}
	if cfg.Client == nil {
		cfg.Client = newClient()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Jitter == nil {
		cfg.Jitter = func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
			if err != nil {
				return 0
			}
			return time.Duration(n.Int64())
		}
	}
	s := &Service{repo: repo, cfg: cfg, logger: log.With("component", "version-check")}
	if cfg.Enabled && !s.Configured() {
		// Once per process: without a pinned key nothing is fetched, and the
		// sensor and SDK versions stay the ones built into this release.
		s.logger.Warn("version check: no release feed key is pinned in this build; no release information is fetched and the built-in sensor and SDK versions apply")
	}
	return s
}

// newClient is the SSRF-guarded client with a redirect cap; it never follows
// a redirect to plain http.
func newClient() *http.Client {
	c := httpsec.SafeHTTPClient(FetchTimeout)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect away from https")
		}
		return nil
	}
	return c
}

// Configured reports whether this build pins a release feed root.
func (s *Service) Configured() bool { return len(s.cfg.Keys) > 0 }

// RunDue runs the online check when it is due. It never returns an upstream
// failure: an offline or air-gapped instance only records it and backs off.
func (s *Service) RunDue(ctx context.Context) error {
	if !s.Configured() || !s.enabled(ctx) {
		return nil
	}
	now := s.cfg.Now()
	first := now.Add(FirstCheckMin + s.cfg.Jitter(FirstCheckSpread))
	due, err := s.repo.ClaimDue(ctx, now, first, now.Add(CheckInterval+s.cfg.Jitter(CheckJitter)))
	if err != nil {
		return fmt.Errorf("version check: claim: %w", err)
	}
	if !due {
		return nil
	}
	st, err := s.repo.Get(ctx)
	if err != nil {
		return fmt.Errorf("version check: state: %w", err)
	}
	raw, code, err := s.fetch(ctx)
	if err == nil {
		var v *releasefeed.Verified
		if v, code, err = s.apply(ctx, st, raw, OriginOnline); err == nil {
			s.publish(&v.Feed)
		}
	}
	if err != nil {
		failures, rerr := s.repo.RecordFailure(ctx, code, now, func(failures int) time.Time {
			if failures >= OfflineAfter {
				return now.Add(OfflineInterval + s.cfg.Jitter(CheckJitter))
			}
			return now.Add(CheckInterval + s.cfg.Jitter(CheckJitter))
		})
		if rerr != nil {
			return fmt.Errorf("version check: record failure: %w", rerr)
		}
		// A warning when the outcome changes (never silent), then one quiet
		// line per check: an air-gapped instance is not an error.
		if code != st.LastError {
			s.logger.Warn("version check: no usable release feed; the last applied release information (or the built-in versions) stays in use",
				"reason", code, "failures", failures, "url", s.cfg.URL, "error", logger.SanitizeError(err))
		} else {
			s.logger.Info("version check: still no usable release feed", "reason", code, "failures", failures)
		}
	} else if st.LastError != "" {
		s.logger.Info("version check: release feed applied again", "previous_reason", st.LastError)
	}
	return nil
}

func (s *Service) fetch(ctx context.Context) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return nil, ErrCodeUnreachable, err
	}
	// Nothing that identifies the instance: no version, no id, no cookies.
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, ErrCodeUnreachable, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrCodeNotPublished, errors.New("status 404: no release feed is published at this address")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, ErrCodeHTTPStatus, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := httpsec.ReadLimited(resp.Body, releasefeed.MaxBundleBytes)
	if err != nil {
		if errors.Is(err, httpsec.ErrBodyTooLarge) {
			return nil, ErrCodeTooLarge, err
		}
		return nil, ErrCodeUnreachable, err
	}
	return raw, "", nil
}

// apply verifies raw against the stored state and stores it.
func (s *Service) apply(ctx context.Context, st State, raw []byte, origin string) (*releasefeed.Verified, string, error) {
	now := s.cfg.Now()
	v, err := releasefeed.Verify(raw, releasefeed.Trust{Keys: s.cfg.Keys, MinSequence: st.AppliedSequence}, now)
	if err != nil {
		return nil, codeOf(err), err
	}
	if v.Feed.Sequence == st.AppliedSequence && st.FeedDigest != "" && v.Digest != st.FeedDigest {
		return nil, ErrCodeConflict, errSequenceConflict
	}
	stored, err := s.repo.Apply(ctx, v, origin, now)
	if err != nil {
		return nil, ErrCodeUnreachable, fmt.Errorf("store: %w", err)
	}
	if !stored {
		return nil, ErrCodeRollback, releasefeed.ErrRollback
	}
	return v, "", nil
}

// errSequenceConflict: a feed with the applied sequence but other content.
// The publisher never signs two feeds with one sequence, so it is a replay or
// a signing fault; the stored one stays.
var errSequenceConflict = errors.New("another release feed with the applied sequence")

func codeOf(err error) string {
	switch {
	case errors.Is(err, releasefeed.ErrNoKey):
		return ErrCodeNoKey
	case errors.Is(err, releasefeed.ErrRollback):
		return ErrCodeRollback
	case errors.Is(err, releasefeed.ErrExpired):
		return ErrCodeExpired
	}
	return ErrCodeInvalid
}

// ImportError is a refused offline import, with its code.
type ImportError struct {
	Code string
	Err  error
}

func (e *ImportError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *ImportError) Unwrap() error { return e.Err }

// Import applies an administrator's copy of the release feed file. It is
// verified exactly like a fetched one, rollback and expiry included.
func (s *Service) Import(ctx context.Context, raw []byte) (*releasefeed.Verified, error) {
	if !s.Configured() {
		return nil, &ImportError{Code: ErrCodeNoKey, Err: releasefeed.ErrNoKey}
	}
	if len(raw) > releasefeed.MaxBundleBytes {
		return nil, &ImportError{Code: ErrCodeTooLarge, Err: httpsec.ErrBodyTooLarge}
	}
	st, err := s.repo.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("version check: state: %w", err)
	}
	v, code, err := s.apply(ctx, st, raw, OriginImport)
	if err != nil {
		if code == ErrCodeUnreachable { // the store failed, not the file
			return nil, err
		}
		return nil, &ImportError{Code: code, Err: err}
	}
	s.publish(&v.Feed)
	return v, nil
}

// Refresh loads the applied feed and hands it to OnFeed. Every replica calls
// it at start-up and on each controller tick, so a feed one replica fetched
// (or an administrator imported) reaches all of them within the hour.
func (s *Service) Refresh(ctx context.Context) error {
	if s.cfg.OnFeed == nil {
		return nil
	}
	st, err := s.repo.Get(ctx)
	if err != nil {
		return fmt.Errorf("version check: state: %w", err)
	}
	s.publish(st.Feed)
	return nil
}

func (s *Service) publish(f *releasefeed.Feed) {
	if s.cfg.OnFeed != nil {
		s.cfg.OnFeed(f)
	}
}

// View is what the console shows.
type View struct {
	// Enabled: the daily online check is on (the environment ceiling and the
	// console switch together).
	Enabled bool `json:"enabled"`
	// LockedByEnvironment: VERSION_CHECK_ENABLED=false keeps it off; the
	// console cannot turn it on.
	LockedByEnvironment bool `json:"locked_by_environment"`
	// Configured: this build pins a release feed root.
	Configured bool   `json:"configured"`
	FeedURL    string `json:"feed_url"`
	// Source is where the applied feed came from (online, import), "" when
	// none was applied.
	Source        string     `json:"source,omitempty"`
	AppliedAt     *time.Time `json:"applied_at,omitempty"`
	FeedIssuedAt  *time.Time `json:"feed_issued_at,omitempty"`
	FeedExpiresAt *time.Time `json:"feed_expires_at,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	// LastError is the code of the last failed online check, "" after a
	// success.
	LastError   string     `json:"last_error,omitempty"`
	NextCheckAt *time.Time `json:"next_check_at,omitempty"`
	// Components are the first-party sensor and SDK releases the applied
	// feed lists (what the Sensors page and the install snippets use).
	Components []releasefeed.Component `json:"components"`
	releasefeed.Status
}

// View returns the console view.
func (s *Service) View(ctx context.Context) (View, error) {
	st, err := s.repo.Get(ctx)
	if err != nil {
		return View{}, err
	}
	enabled := s.enabled(ctx)
	v := View{Enabled: enabled, LockedByEnvironment: !s.cfg.Enabled, Configured: s.Configured(), FeedURL: s.cfg.URL, Source: st.Origin,
		AppliedAt: st.AppliedAt, LastAttemptAt: st.LastAttemptAt, LastError: st.LastError,
		Status: releasefeed.Evaluate(st.Feed, s.cfg.Running, s.cfg.Now()), Components: []releasefeed.Component{}}
	if s.cfg.Enabled && s.Configured() {
		v.NextCheckAt = st.NextCheckAt
	}
	if st.Feed != nil {
		issued, expires := st.Feed.IssuedAt, st.Feed.ExpiresAt
		v.FeedIssuedAt, v.FeedExpiresAt = &issued, &expires
		v.Components = append(v.Components, st.Feed.Components...)
	}
	return v, nil
}
