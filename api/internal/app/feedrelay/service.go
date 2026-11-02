// Package feedrelay is the platform side of the feed relay
// (docs/rfcs/RFC-142-feed-relay.md): a platform with no outbound access
// receives its signed feeds through platform-owned sensors that have
// internet access.
//
// The relay is a pipe for files and adds no trust. The platform plans which
// files of a feed it needs (rounds), a designated relay sensor claims a
// round, downloads exactly those files from fixed feed origins and streams
// them back. The files land in the relay spool, a Postgres table shared by
// every API replica; the replica holding the feed-relay controller lease
// copies them into a local working directory, and the existing importers
// read that directory as their only origin, with every signature, key-set,
// sequence, expiry, size and digest check unchanged. A relay can withhold
// files; it cannot get anything applied that the feed's pinned root did not
// sign.
//
// Who may relay: only the platform (instance-scope) sensors the super
// administrator designated (one to three), active, reporting feed.relay@1.
// Any of them claims the oldest open round, so a second relay takes over
// when one goes away. Rounds are signed by the job signer (command type
// feed_relay, the platform tenant id, instance scope, the feed origins as
// targets, which the signer checks against its own allowlist).
//
// Import is single-runner: the feed-relay controller is exclusive (one
// replica holds its lease) and the importer takes its own run guard.
package feedrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Capability is what a relay sensor reports.
const Capability = "feed.relay@1"

// ModeKey is the setting: the feed category of the outbound connections
// registry (research/381), holding the mode (direct, the default, or relay)
// and the designated relay sensors, saved together.
const ModeKey = "egress.mode.feeds"

// Modes.
const (
	ModeDirect = "direct"
	ModeRelay  = "relay"
)

// Admin audit action of a change.
const ActionChanged = "platform.feed_delivery_changed"

// MaxRelays is the number of sensors that may be designated.
const MaxRelays = 3

// Limits.
const (
	// MaxFileBytes caps one relayed file (the largest today is about 6 MB).
	MaxFileBytes = 32 << 20
	// maxRoundBytes caps what one round may deliver (the planner asks for
	// less).
	maxRoundBytes = 256 << 20
	// spoolQuota caps the spool (steady state is about 70 MB).
	spoolQuota    = 512 << 20
	maxReportRows = 512
	roundTTL      = 30 * time.Minute
	// claimStale: a claim with nothing uploaded after this may be taken by
	// another designated sensor.
	claimStale = 10 * time.Minute
	// relayOffline: no designated sensor seen for this long.
	relayOffline = 10 * time.Minute
	// clearAfter: the spool is emptied after this long in direct mode.
	clearAfter = 7 * 24 * time.Hour
	retention  = 7 * 24 * time.Hour
)

// Retry-After hints of an empty answer to a relay sensor.
const (
	// RetryInCycle: a cycle is in progress; the next round is planned on the
	// controller's next tick.
	RetryInCycle = 15 * time.Second
	// RetryIdle: nothing to do until the next cycle.
	RetryIdle = time.Minute
	// RetryNotDesignated: an eligible sensor that is not designated (or the
	// platform is in direct mode) asks again much later.
	RetryNotDesignated = 10 * time.Minute
)

// Errors.
var (
	// ErrNotRelay answers a sensor that may not relay (not a platform
	// sensor, not active, no feed.relay@1, or not designated for an upload).
	// One error for every reason.
	ErrNotRelay = fmt.Errorf("%w: this sensor does not relay feeds", shared.ErrForbidden)
	// ErrRoundClosed: the round is not open, expired, or another sensor's.
	ErrRoundClosed = dom.ErrRoundClosed
	// ErrFileRefused: the upload is not a file of the round, its size or
	// digest is not the one declared or pinned, or the file was already
	// uploaded in this round with other bytes.
	ErrFileRefused = fmt.Errorf("%w: file refused", shared.ErrValidation)
	// ErrQuota: the round's byte budget or the spool's quota is exhausted.
	ErrQuota = fmt.Errorf("%w: feed relay quota exceeded", shared.ErrValidation)
	// ErrInvalid: the setting is not valid.
	ErrInvalid = fmt.Errorf("%w: mode must be direct or relay; relay needs one to three active platform sensors that report feed.relay@1", shared.ErrValidation)
	// ErrLocked: a feed bundle directory is configured, or no job signer.
	ErrLocked  = fmt.Errorf("%w: relay mode is not available on this installation", shared.ErrConflict)
	ErrNoActor = errors.New("a feed delivery change needs an administrator")
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Signer signs a statement (internal/infra/signer.Client).
type Signer interface {
	SignJob(ctx context.Context, st jobsign.Statement) (json.RawMessage, error)
}

// Sensors reads a sensor by id without tenant scope (only instance-scope
// sensors are ever accepted).
type Sensors interface {
	GetByID(ctx context.Context, id shared.ID) (*sensor.Sensor, error)
}

// Plan is what a feed wants next.
type Plan struct {
	Phase string
	Files []dom.File
	// Ready: nothing is missing; Import may run.
	Ready bool
}

// Freshness is what a feed last applied.
type Freshness struct {
	// Sequence is the applied release sequence (0: unknown or none).
	Sequence uint64
	// PublishedAt is when the applied release was created by its
	// publisher; now minus this is the feed's age.
	PublishedAt *time.Time
}

// Feed plans and imports one feed from its local working directory.
type Feed interface {
	Name() string
	// Origins are the feed origins the relay downloads from (canonical).
	Origins() []string
	// Interval between cycles.
	Interval() time.Duration
	// Head is the first round of a cycle.
	Head() Plan
	// Plan reads the working directory after a delivered round.
	Plan(ctx context.Context, dir string) (Plan, error)
	// Import applies the working directory and returns the file names the
	// current release still needs (the rest is pruned).
	Import(ctx context.Context, dir string) (keep []string, err error)
	// Freshness reports what the feed last applied.
	Freshness(ctx context.Context) (Freshness, error)
}

// feedSetting is the stored setting.
type feedSetting struct {
	Mode      string   `json:"mode"`
	SensorIDs []string `json:"sensor_ids,omitempty"`
	// BootstrapToken is the instance enrollment token of a new install's
	// bundled sensor: the sensor that enrolls with it is designated once
	// (the install chose relay mode), then the field is cleared.
	BootstrapToken string `json:"bootstrap_token,omitempty"`
}

// Config configures the service.
type Config struct {
	// WorkDir is the local working directory the lease holder copies the
	// spool into (one subdirectory per feed); never shared.
	WorkDir string
	Signer  Signer
	// Locked is why relay mode cannot be chosen ("" when it can): a feed
	// bundle directory or no signer.
	Locked string
	// NotRelayed names feeds that stay idle in relay mode (shown in the
	// console, never silently idle).
	NotRelayed []string
	Now        func() time.Time
}

// Service is the platform side of the relay.
type Service struct {
	cfg      Config
	repo     dom.Repository
	spool    dom.Spool
	sensors  Sensors
	setting  *consolesetting.Store[feedSetting]
	settings platformsetting.Repository
	recorder *consolesetting.Recorder
	feeds    map[string]Feed
	order    []string
	logger   *logger.Logger

	mu sync.Mutex
	// local is what the working directory holds (feed -> name -> sha256),
	// written by this process.
	local map[string]map[string]string
}

// NewService creates the service.
func NewService(cfg Config, repo dom.Repository, spool dom.Spool, sensors Sensors, settings platformsetting.Repository, recorder *consolesetting.Recorder, log *logger.Logger) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Signer == nil && cfg.Locked == "" {
		cfg.Locked = "no_signer"
	}
	return &Service{cfg: cfg, repo: repo, spool: spool, sensors: sensors, settings: settings, recorder: recorder,
		feeds: map[string]Feed{}, local: map[string]map[string]string{},
		setting: consolesetting.NewStore[feedSetting](settings, ModeKey),
		logger:  log.With("service", "feed_relay")}
}

// AddFeed registers a feed.
func (s *Service) AddFeed(f Feed) {
	s.feeds[f.Name()] = f
	s.order = append(s.order, f.Name())
}

// Dir is the local working directory of a feed.
func (s *Service) Dir(feed string) string { return filepath.Join(s.cfg.WorkDir, feed) }

// RelayMode reports whether the platform receives its feeds through the
// relay (then it makes no outbound feed request at all). A setting that
// cannot be read counts as relay: never an automatic fallback to direct.
func (s *Service) RelayMode(ctx context.Context) bool {
	if s == nil || s.cfg.Locked != "" {
		return false
	}
	m, _, err := s.setting.Get(ctx)
	return err != nil || m.Mode == ModeRelay
}

// DirIfRelay is the importer hook: the feed's working directory in relay
// mode, else "".
func (s *Service) DirIfRelay(feed string) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		if !s.RelayMode(ctx) {
			return ""
		}
		return s.Dir(feed)
	}
}

// Settings is what an administrator sees.
type Settings struct {
	Mode      string
	SensorIDs []string
	Locked    string
	Version   int
	UpdatedAt time.Time
	// Bootstrap: relay mode chosen at install; the bundled sensor is
	// designated once it enrolls.
	Bootstrap bool
}

// Get returns the setting.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	m, meta, err := s.setting.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	mode := m.Mode
	if mode != ModeRelay || s.cfg.Locked != "" {
		mode = ModeDirect
	}
	ids := m.SensorIDs
	if ids == nil {
		ids = []string{}
	}
	return Settings{Mode: mode, SensorIDs: ids, Locked: s.cfg.Locked, Version: meta.Version, UpdatedAt: meta.UpdatedAt,
		Bootstrap: m.BootstrapToken != ""}, nil
}

// eligible reports whether sn may relay at all.
func eligible(sn *sensor.Sensor) bool {
	return sn != nil && sn.IsShared() && sn.TenantID == nil && sn.Status == sensor.SensorStatusActive && sn.HasCapability(Capability)
}

// Update stores the mode and the designated sensors in one write. The
// caller checked the super administrator role and the step-up.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, mode string, sensorIDs []string, expectedVersion int, ip, ua string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if mode != ModeDirect && mode != ModeRelay {
		return Settings{}, ErrInvalid
	}
	if mode == ModeRelay && s.cfg.Locked != "" {
		return Settings{}, ErrLocked
	}
	ids, err := s.validSensors(ctx, sensorIDs)
	if err != nil {
		return Settings{}, err
	}
	if mode == ModeRelay && len(ids) == 0 {
		return Settings{}, ErrInvalid
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.setting.Put(ctx, feedSetting{Mode: mode, SensorIDs: ids}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	if s.recorder != nil {
		s.recorder.Record(ctx, actor, consolesetting.Change{
			Action: ActionChanged, Key: ModeKey, Title: "Feed delivery",
			Method: "PUT", Path: "/api/v1/admin/settings/feed-relay",
			Details: map[string]any{"previous_mode": prev.Mode, "previous_sensor_ids": prev.SensorIDs, "mode": mode, "sensor_ids": ids},
		}, ip, ua)
	}
	return s.Get(ctx)
}

// validSensors checks the designation: at most MaxRelays distinct active
// platform sensors that report feed.relay@1. Canonical ids come back.
func (s *Service) validSensors(ctx context.Context, raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(strings.TrimSpace(r))
		if err != nil {
			return nil, ErrInvalid
		}
		if slices.Contains(out, id.String()) {
			continue
		}
		sn, err := s.sensors.GetByID(ctx, id)
		if err != nil || !eligible(sn) {
			return nil, ErrInvalid
		}
		out = append(out, id.String())
	}
	if len(out) > MaxRelays {
		return nil, ErrInvalid
	}
	return out, nil
}

// SeedRelayMode is the install step of a new installation whose bundled
// sensor setup chose relay mode: it stores relay mode with the bundled
// sensor's enrollment token, only when the setting was never written (an
// existing installation has a direct row since the feed relay migration).
// It reports whether it wrote the setting.
func SeedRelayMode(ctx context.Context, settings platformsetting.Repository, tokenID shared.ID) (bool, error) {
	raw, err := json.Marshal(feedSetting{Mode: ModeRelay, BootstrapToken: tokenID.String()})
	if err != nil {
		return false, err
	}
	return settings.CreateIfAbsent(ctx, ModeKey, platformsetting.State{
		Value: raw, Version: 1, Source: platformsetting.SourceConsole, UpdatedAt: time.Now().UTC(),
	})
}

// designated returns the designated sensor ids.
func designated(m feedSetting) []shared.ID {
	out := make([]shared.ID, 0, len(m.SensorIDs))
	for _, r := range m.SensorIDs {
		if id, err := shared.IDFromString(r); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// errNotDesignated: an eligible sensor that is not designated now (or
// direct mode).
var errNotDesignated = errors.New("not designated")

// admit returns the designated ids when sn may serve rounds now.
func (s *Service) admit(ctx context.Context, sn *sensor.Sensor) ([]shared.ID, error) {
	if !eligible(sn) {
		return nil, ErrNotRelay
	}
	if s.cfg.Locked != "" {
		return nil, errNotDesignated
	}
	m, _, err := s.setting.Get(ctx)
	if err != nil {
		return nil, err
	}
	ids := designated(m)
	if m.Mode != ModeRelay || !slices.Contains(ids, sn.ID) {
		return nil, errNotDesignated
	}
	return ids, nil
}

// payload is the signed payload of a round (the sensor's feedrelay.Payload).
type payload struct {
	Feed    string     `json:"feed"`
	Targets []string   `json:"targets"`
	Files   []dom.File `json:"files"`
}

// Next is a round with its exact payload bytes and the signed statement.
type Next struct {
	ID        string          `json:"id"`
	Payload   json.RawMessage `json:"payload"`
	SignedJob json.RawMessage `json:"signed_job"`
}

// Next claims the relay sensor's next round and signs it now. With no round
// it returns nil and how long the sensor should wait before asking again.
func (s *Service) Next(ctx context.Context, sn *sensor.Sensor) (*Next, time.Duration, error) {
	ids, err := s.admit(ctx, sn)
	if errors.Is(err, errNotDesignated) {
		return nil, RetryNotDesignated, nil
	}
	if err != nil {
		return nil, 0, err
	}
	now := s.cfg.Now()
	rd, err := s.repo.Claim(ctx, dom.ClaimRule{SensorID: sn.ID, Designated: ids, StaleBefore: now.Add(-claimStale), Now: now})
	if err != nil {
		return nil, 0, err
	}
	if rd == nil {
		return nil, s.idleRetry(ctx), nil
	}
	pb, err := json.Marshal(payload{Feed: rd.Feed, Targets: rd.Origins, Files: rd.Files})
	if err != nil {
		return nil, 0, err
	}
	expires := now.Add(jobsign.MaxTTL)
	if rd.ExpiresAt.Before(expires) {
		expires = rd.ExpiresAt
	}
	env, err := s.cfg.Signer.SignJob(ctx, jobsign.Statement{
		Kind: jobsign.Kind, TenantID: jobsign.PlatformTenantID, SensorID: sn.ID.String(),
		SensorScope: jobsign.SensorScopeInstance, CommandID: rd.ID.String(), CommandType: jobsign.CommandTypeFeedRelay,
		Tool: "", PayloadSHA256: jobsign.PayloadDigest(pb), Targets: rd.Origins,
		IssuedAt: now.UTC(), ExpiresAt: expires.UTC(),
	})
	var rf *jobsign.RefusalError
	if errors.As(err, &rf) {
		// The signer will refuse this round again (an origin outside
		// SIGNER_FEED_ORIGINS, for example): close it with the reason the
		// console shows, and back off like any failed cycle.
		detail := clip(rf.Reason, 64)
		if d := printable(rf.Detail, 200); d != "" {
			detail += ": " + d
		}
		s.logger.Warn("feed relay: the job signer refused a round", "feed", rd.Feed, "reason", clip(rf.Reason, 64))
		if ferr := s.repo.Fail(ctx, rd.ID, dom.CodeSignerRefused, detail, now); ferr != nil {
			return nil, 0, ferr
		}
		return nil, RetryIdle, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("sign feed relay round: %w", err)
	}
	return &Next{ID: rd.ID.String(), Payload: pb, SignedJob: env}, 0, nil
}

// idleRetry is RetryInCycle while a feed's cycle waits for its next plan,
// else RetryIdle.
func (s *Service) idleRetry(ctx context.Context) time.Duration {
	for _, name := range s.order {
		last, err := s.repo.Latest(ctx, name)
		if err == nil && last != nil && last.Status == dom.StatusDone && isFileRound(last) {
			return RetryInCycle
		}
	}
	return RetryIdle
}

func isFileRound(rd *dom.Round) bool {
	return rd.Phase != dom.PhaseImported && rd.Phase != dom.PhaseFailed
}

// Receive takes one file of a round the sensor claimed. size is the
// request's Content-Length, digest the hex SHA-256 its Content-Digest
// declared. The body is read under the file's cap, hashed and checked
// against the declaration and the round's pin; only a file that matches is
// stored in the spool.
func (s *Service) Receive(ctx context.Context, sn *sensor.Sensor, roundID, name string, body io.Reader, size int64, digest string) error {
	if _, err := s.admit(ctx, sn); err != nil {
		if errors.Is(err, errNotDesignated) {
			return ErrNotRelay
		}
		return err
	}
	rd, err := s.openRound(ctx, sn, roundID)
	if err != nil {
		return err
	}
	f, ok := rd.File(name)
	if !ok || !nameRe.MatchString(name) {
		return ErrFileRefused
	}
	limit := min(f.MaxBytes, MaxFileBytes)
	if size < 0 || size > limit || (f.Size > 0 && size != f.Size) || len(digest) != 64 {
		return ErrFileRefused
	}
	var buf bytes.Buffer
	buf.Grow(int(size))
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(&buf, h), io.LimitReader(body, size+1))
	if err != nil {
		return fmt.Errorf("receive feed relay file: %w", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n != size || sum != digest || (f.SHA256 != "" && sum != f.SHA256) {
		s.logger.Warn("feed relay: file refused", "round_id", rd.ID.String(), "file", name, "bytes", n)
		return ErrFileRefused
	}
	err = s.spool.Store(ctx, dom.Upload{RoundID: rd.ID, SensorID: sn.ID, Feed: rd.Feed, Name: name, SHA256: sum,
		Data: buf.Bytes(), RoundBudget: maxRoundBytes, SpoolQuota: spoolQuota, Now: s.cfg.Now()})
	switch {
	case errors.Is(err, dom.ErrDuplicate):
		return ErrFileRefused
	case errors.Is(err, dom.ErrRoundFull), errors.Is(err, dom.ErrSpoolFull):
		s.logger.Warn("feed relay: quota", "round_id", rd.ID.String(), "file", name, "error", err)
		return ErrQuota
	}
	return err
}

// Done closes a round with the relay's report.
func (s *Service) Done(ctx context.Context, sn *sensor.Sensor, roundID string, rep dom.Report) error {
	if _, err := s.admit(ctx, sn); err != nil {
		if errors.Is(err, errNotDesignated) {
			return ErrNotRelay
		}
		return err
	}
	rd, err := s.openRound(ctx, sn, roundID)
	if err != nil {
		return err
	}
	rep = sanitize(rep, rd)
	status := dom.StatusDone
	if rep.Refused != "" {
		status = dom.StatusRefused
	}
	ok, err := s.repo.Finish(ctx, rd.ID, sn.ID, status, &rep, s.cfg.Now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrRoundClosed
	}
	return nil
}

func (s *Service) openRound(ctx context.Context, sn *sensor.Sensor, roundID string) (*dom.Round, error) {
	id, err := shared.IDFromString(roundID)
	if err != nil {
		return nil, ErrRoundClosed
	}
	rd, err := s.repo.GetForSensor(ctx, id, sn.ID)
	if errors.Is(err, dom.ErrNotFound) {
		return nil, ErrRoundClosed
	}
	if err != nil {
		return nil, err
	}
	if rd.Status != dom.StatusOpen || !s.cfg.Now().Before(rd.ExpiresAt) {
		return nil, ErrRoundClosed
	}
	return rd, nil
}

// sanitize keeps only rows for the round's files, with bounded codes.
func sanitize(rep dom.Report, rd *dom.Round) dom.Report {
	out := dom.Report{Refused: clip(rep.Refused, 64)}
	seen := map[string]bool{}
	for _, o := range rep.Files {
		if len(out.Files) >= maxReportRows {
			break
		}
		if _, ok := rd.File(o.Name); !ok || seen[o.Name] {
			continue
		}
		seen[o.Name] = true
		out.Files = append(out.Files, dom.Outcome{Name: o.Name, Status: clip(o.Status, 16), Code: clip(o.Code, 64), Bytes: max(o.Bytes, 0)})
	}
	return out
}

// clip keeps at most n characters of [a-z0-9_-].
func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// printable keeps at most n printable ASCII characters (a signer detail is
// our own text, still never trusted as markup).
func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			break
		}
		if r >= 0x20 && r < 0x7f && r != '<' && r != '>' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// Reconcile drives every feed one step (the controller, on the replica
// holding its lease). It returns the rounds created.
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	now := s.cfg.Now()
	if _, err := s.repo.ExpireOpen(ctx, now); err != nil {
		return 0, err
	}
	if _, err := s.repo.DeleteBefore(ctx, now.Add(-retention)); err != nil {
		s.logger.Warn("feed relay: retention", "error", err)
	}
	if !s.RelayMode(ctx) {
		s.clearIfDirect(ctx, now)
		return 0, nil
	}
	m, meta, err := s.setting.Get(ctx)
	if err != nil {
		return 0, err
	}
	if m.BootstrapToken != "" && len(m.SensorIDs) == 0 {
		m = s.bootstrap(ctx, m, meta)
	}
	if len(designated(m)) == 0 {
		return 0, nil // relay mode without a relay: the console says so
	}
	created := 0
	for _, name := range s.order {
		n, err := s.step(ctx, s.feeds[name], now)
		if err != nil {
			s.logger.Warn("feed relay: step", "feed", name, "error", logger.SanitizeError(err))
		}
		created += n
	}
	return created, nil
}

// clearIfDirect empties the spool once the platform has been in direct
// mode (or locked) for clearAfter.
func (s *Service) clearIfDirect(ctx context.Context, now time.Time) {
	_, meta, err := s.setting.Get(ctx)
	if err != nil || (meta.Stored && now.Sub(meta.UpdatedAt) < clearAfter && s.cfg.Locked == "") {
		return
	}
	if n, err := s.spool.Clear(ctx); err != nil {
		s.logger.Warn("feed relay: clear spool", "error", err)
	} else if n > 0 {
		s.logger.Info("feed relay: spool cleared after direct mode", "files", n)
	}
}

// bootstrap designates a new install's bundled sensor once it enrolled
// with the token the install registered, and reports the setting as it is
// afterwards.
func (s *Service) bootstrap(ctx context.Context, m feedSetting, meta consolesetting.Meta) feedSetting {
	tok, err := shared.IDFromString(m.BootstrapToken)
	if err != nil {
		return m
	}
	id, err := s.repo.BootstrapSensor(ctx, tok)
	if err != nil || id == nil {
		return m
	}
	sn, err := s.sensors.GetByID(ctx, *id)
	if err != nil || !eligible(sn) {
		return m // not active or not reporting feed.relay@1 yet
	}
	next := feedSetting{Mode: m.Mode, SensorIDs: []string{id.String()}}
	if _, err := s.setting.Put(ctx, next, meta.Version, shared.ID{}); err != nil {
		s.logger.Warn("feed relay: designate the bundled sensor", "error", err)
		return m
	}
	s.logger.Info("feed relay: bundled sensor designated as the relay", "sensor_id", id.String())
	return next
}

// step moves one feed forward: wait for an open round, back off after a
// failure, start a cycle with the head, plan after a delivered round, and
// import when nothing is missing.
func (s *Service) step(ctx context.Context, f Feed, now time.Time) (int, error) {
	last, err := s.repo.Latest(ctx, f.Name())
	if err != nil {
		return 0, err
	}
	backoff := min(f.Interval(), 10*time.Minute)
	switch {
	case last == nil:
		return s.create(ctx, f, f.Head(), now)
	case last.Status == dom.StatusOpen:
		return 0, nil
	case last.Phase == dom.PhaseImported:
		if now.Sub(last.CreatedAt) < f.Interval() {
			return 0, nil
		}
		return s.create(ctx, f, f.Head(), now)
	case last.Phase == dom.PhaseFailed, last.Status != dom.StatusDone:
		// failed, refused or expired
		if now.Sub(last.CreatedAt) < backoff {
			return 0, nil
		}
		return s.create(ctx, f, f.Head(), now)
	case last.Delivered() == 0:
		code := dom.CodeNothingDelivered
		if last.HasOutcomeCode("not_found") {
			code = dom.CodeUpstreamMissing
		}
		return 0, s.close(ctx, f, dom.PhaseFailed, code, now)
	}
	dir, err := s.materialize(ctx, f.Name())
	if err != nil {
		return 0, err
	}
	p, err := f.Plan(ctx, dir)
	if err != nil {
		s.logger.Warn("feed relay: relayed files refused", "feed", f.Name(), "error", logger.SanitizeError(err))
		return 0, s.close(ctx, f, dom.PhaseFailed, failureCode(err, last, dom.CodePlanFailed), now)
	}
	if !p.Ready {
		return s.create(ctx, f, p, now)
	}
	keep, err := f.Import(ctx, dir)
	if err != nil {
		s.logger.Warn("feed relay: import", "feed", f.Name(), "error", logger.SanitizeError(err))
		return 0, s.close(ctx, f, dom.PhaseFailed, failureCode(err, last, dom.CodeImportFailed), now)
	}
	s.prune(ctx, f.Name(), keep)
	return 0, s.close(ctx, f, dom.PhaseImported, "", now)
}

// failureCode names why the relayed files did not plan or import, from the
// error and the relay's report of the last round.
func failureCode(err error, last *dom.Round, fallback string) string {
	switch {
	case errors.Is(err, bundle.ErrRollback):
		return dom.CodeRollbackRefused
	case errors.Is(err, bundle.ErrPinMismatch):
		return dom.CodePinMismatch
	case errors.Is(err, bundle.ErrSignature):
		return dom.CodeVerifyFailed
	case errors.Is(err, os.ErrNotExist):
		if last != nil && last.HasOutcomeCode("not_found") {
			return dom.CodeUpstreamMissing
		}
		return dom.CodeNothingDelivered
	}
	return fallback
}

func (s *Service) create(ctx context.Context, f Feed, p Plan, now time.Time) (int, error) {
	if len(p.Files) == 0 {
		return 0, nil
	}
	rd := &dom.Round{ID: newID(), Feed: f.Name(), Phase: p.Phase, Status: dom.StatusOpen,
		Origins: f.Origins(), Files: p.Files, CreatedAt: now, ExpiresAt: now.Add(roundTTL)}
	if err := s.repo.Create(ctx, rd); err != nil {
		return 0, err
	}
	return 1, nil
}

// close writes a bookkeeping row (no files, no sensor) that ends a cycle.
func (s *Service) close(ctx context.Context, f Feed, phase, code string, now time.Time) error {
	status := dom.StatusDone
	if phase == dom.PhaseFailed {
		status = dom.StatusFailed
	}
	return s.repo.Create(ctx, &dom.Round{ID: newID(), Feed: f.Name(), Phase: phase, Status: status,
		Origins: []string{}, Files: []dom.File{}, ErrorCode: code, CreatedAt: now, ExpiresAt: now, DeliveredAt: &now})
}

// materialize copies the feed's spool into its local working directory:
// files the directory lacks (or holds with other bytes) are written, files
// with no spool row are removed. It returns the directory.
func (s *Service) materialize(ctx context.Context, feed string) (string, error) {
	dir := s.Dir(feed)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	rows, err := s.spool.List(ctx, feed)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	have := s.local[feed]
	if have == nil {
		have = map[string]string{}
		s.local[feed] = have
	}
	want := map[string]bool{}
	for _, r := range rows {
		if !nameRe.MatchString(r.Name) {
			continue
		}
		want[r.Name] = true
		path := filepath.Join(dir, r.Name)
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() && st.Size() == r.Size && have[r.Name] == r.SHA256 {
			continue
		}
		data, err := s.spool.Read(ctx, feed, r.Name)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != r.SHA256 || int64(len(data)) != r.Size {
			return "", fmt.Errorf("feed relay spool: %s does not match its digest", r.Name)
		}
		if err := writeAtomic(dir, r.Name, data); err != nil {
			return "", err
		}
		have[r.Name] = r.SHA256
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !want[e.Name()] && e.Type().IsRegular() {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			delete(have, e.Name())
		}
	}
	return dir, nil
}

func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".in-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

// prune removes the spool rows and local files the current release no
// longer needs.
func (s *Service) prune(ctx context.Context, feed string, keep []string) {
	if _, err := s.spool.Prune(ctx, feed, keep); err != nil {
		s.logger.Warn("feed relay: prune spool", "feed", feed, "error", err)
		return
	}
	if _, err := s.materialize(ctx, feed); err != nil {
		s.logger.Warn("feed relay: prune working directory", "feed", feed, "error", logger.SanitizeError(err))
	}
}

func newID() shared.ID {
	u, err := uuid.NewRandom()
	if err != nil {
		var b [16]byte
		_, _ = rand.Read(b[:])
		u = uuid.UUID(b)
	}
	id, _ := shared.IDFromString(u.String())
	return id
}
