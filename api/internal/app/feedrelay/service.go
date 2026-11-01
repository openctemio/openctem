// Package feedrelay is the platform side of the feed relay
// (docs/rfcs/RFC-142-feed-relay.md): a platform with no outbound access
// receives its signed feeds through a platform-owned sensor that has
// internet access.
//
// The relay is a pipe for files and adds no trust. The platform plans which
// files of a feed it needs (rounds), the designated relay sensor downloads
// exactly those from fixed feed origins and streams them back, and the
// files land in a local spool directory that the existing importers read as
// their only origin, with every signature, key-set, sequence, expiry, size
// and digest check unchanged. A relay can withhold files; it cannot get
// anything applied that the feed's pinned root did not sign.
//
// Who may relay: only the platform (instance-scope) sensor the super
// administrator designated, active, reporting feed.relay@1. Rounds are
// signed by the job signer (command type feed_relay, the platform tenant
// id, instance scope, the feed origins as targets, which the signer checks
// against its own allowlist).
package feedrelay

import (
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
	"strings"
	"time"

	"github.com/google/uuid"

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

// Setting keys. ModeKey is the feed category of the outbound connections
// registry (research/381): direct (default) or relay.
const (
	ModeKey   = "egress.mode.feeds"
	SensorKey = "feed_relay.sensor"
)

// Modes.
const (
	ModeDirect = "direct"
	ModeRelay  = "relay"
)

// Admin audit action of a change.
const ActionChanged = "platform.feed_delivery_changed"

// Limits.
const (
	maxFileBytes  = 64 << 20
	maxReportRows = 512
	roundTTL      = 30 * time.Minute
	retention     = 7 * 24 * time.Hour
)

// Errors.
var (
	// ErrNotRelay answers a sensor that is not the designated relay (or the
	// platform is not in relay mode). One error for every reason.
	ErrNotRelay = fmt.Errorf("%w: this sensor does not relay feeds", shared.ErrForbidden)
	// ErrRoundClosed: the round is not open (done, expired) or not this
	// sensor's.
	ErrRoundClosed = fmt.Errorf("%w: feed relay round is not open", shared.ErrNotFound)
	// ErrFileRefused: the upload is not a file of the round, or its size or
	// digest is not the one declared or pinned.
	ErrFileRefused = fmt.Errorf("%w: file refused", shared.ErrValidation)
	// ErrInvalid: the setting is not valid.
	ErrInvalid = fmt.Errorf("%w: mode must be direct or relay; relay needs a platform sensor", shared.ErrValidation)
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

// Feed plans and imports one feed from its spool directory.
type Feed interface {
	Name() string
	// Origins are the feed origins the relay downloads from (canonical).
	Origins() []string
	// Interval between cycles.
	Interval() time.Duration
	// Head is the first round of a cycle.
	Head() Plan
	// Plan reads the spool after a delivered round.
	Plan(ctx context.Context, dir string) (Plan, error)
	// Import applies the spool; prune removes files no longer needed.
	Import(ctx context.Context, dir string) error
}

type modeSetting struct {
	Mode string `json:"mode"`
}

type sensorSetting struct {
	SensorID string `json:"sensor_id"`
}

// Config configures the service.
type Config struct {
	Spool  string
	Signer Signer
	// Locked is why relay mode cannot be chosen ("" when it can): a feed
	// bundle directory or no signer.
	Locked string
	Now    func() time.Time
}

// Service is the platform side of the relay.
type Service struct {
	cfg      Config
	repo     dom.Repository
	sensors  Sensors
	mode     *consolesetting.Store[modeSetting]
	relay    *consolesetting.Store[sensorSetting]
	recorder *consolesetting.Recorder
	feeds    map[string]Feed
	order    []string
	logger   *logger.Logger
}

// NewService creates the service.
func NewService(cfg Config, repo dom.Repository, sensors Sensors, settings platformsetting.Repository, recorder *consolesetting.Recorder, log *logger.Logger) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Signer == nil && cfg.Locked == "" {
		cfg.Locked = "no_signer"
	}
	return &Service{cfg: cfg, repo: repo, sensors: sensors, recorder: recorder, feeds: map[string]Feed{},
		mode:   consolesetting.NewStore[modeSetting](settings, ModeKey),
		relay:  consolesetting.NewStore[sensorSetting](settings, SensorKey),
		logger: log.With("service", "feed_relay")}
}

// AddFeed registers a feed.
func (s *Service) AddFeed(f Feed) {
	s.feeds[f.Name()] = f
	s.order = append(s.order, f.Name())
}

// Dir is the spool directory of a feed.
func (s *Service) Dir(feed string) string { return filepath.Join(s.cfg.Spool, feed) }

// RelayMode reports whether the platform receives its feeds through the
// relay (then it makes no outbound feed request at all). A setting that
// cannot be read counts as relay when it was relay last time it was read
// (the store's cache), else direct.
func (s *Service) RelayMode(ctx context.Context) bool {
	if s == nil || s.cfg.Locked != "" {
		return false
	}
	m, _, err := s.mode.Get(ctx)
	return err == nil && m.Mode == ModeRelay
}

// SpoolIfRelay is the importer hook: the feed's spool in relay mode, else "".
func (s *Service) SpoolIfRelay(feed string) func(ctx context.Context) string {
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
	SensorID  string
	Locked    string
	Version   int
	UpdatedAt time.Time
}

// Get returns the setting.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	m, meta, err := s.mode.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	r, _, err := s.relay.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	mode := m.Mode
	if mode != ModeRelay || s.cfg.Locked != "" {
		mode = ModeDirect
	}
	return Settings{Mode: mode, SensorID: r.SensorID, Locked: s.cfg.Locked, Version: meta.Version, UpdatedAt: meta.UpdatedAt}, nil
}

// Update stores the mode and the designated sensor. The caller checked the
// super administrator role and the step-up.
func (s *Service) Update(ctx context.Context, actor *admin.AdminUser, mode, sensorID string, expectedVersion int, ip, ua string) (Settings, error) {
	if actor == nil {
		return Settings{}, ErrNoActor
	}
	if mode != ModeDirect && mode != ModeRelay {
		return Settings{}, ErrInvalid
	}
	if mode == ModeRelay && s.cfg.Locked != "" {
		return Settings{}, ErrLocked
	}
	if mode == ModeRelay || sensorID != "" {
		id, err := shared.IDFromString(sensorID)
		if err != nil {
			return Settings{}, ErrInvalid
		}
		sn, err := s.sensors.GetByID(ctx, id)
		if err != nil || sn == nil || !sn.IsShared() || sn.Status != sensor.SensorStatusActive {
			return Settings{}, ErrInvalid
		}
	}
	prev, err := s.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.mode.Put(ctx, modeSetting{Mode: mode}, expectedVersion, actor.ID()); err != nil {
		return Settings{}, err
	}
	_, rmeta, err := s.relay.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	if _, err := s.relay.Put(ctx, sensorSetting{SensorID: sensorID}, rmeta.Version, actor.ID()); err != nil {
		return Settings{}, err
	}
	if s.recorder != nil {
		s.recorder.Record(ctx, actor, consolesetting.Change{
			Action: ActionChanged, Key: ModeKey, Title: "Feed delivery",
			Method: "PUT", Path: "/api/v1/admin/settings/feed-relay",
			Details: map[string]any{"previous_mode": prev.Mode, "previous_sensor_id": prev.SensorID, "mode": mode, "sensor_id": sensorID},
		}, ip, ua)
	}
	return s.Get(ctx)
}

// relaySensor returns the designated sensor when sn is it and may relay.
func (s *Service) admit(ctx context.Context, sn *sensor.Sensor) error {
	if sn == nil || !sn.IsShared() || sn.Status != sensor.SensorStatusActive || !sn.HasCapability(Capability) {
		return ErrNotRelay
	}
	if !s.RelayMode(ctx) {
		return ErrNotRelay
	}
	r, _, err := s.relay.Get(ctx)
	if err != nil || r.SensorID == "" || !strings.EqualFold(r.SensorID, sn.ID.String()) {
		return ErrNotRelay
	}
	return nil
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

// Next returns the relay sensor's next open round, signed now; nil when
// there is none.
func (s *Service) Next(ctx context.Context, sn *sensor.Sensor) (*Next, error) {
	if err := s.admit(ctx, sn); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	rd, err := s.repo.NextOpen(ctx, sn.ID, now)
	if err != nil || rd == nil {
		return nil, err
	}
	pb, err := json.Marshal(payload{Feed: rd.Feed, Targets: rd.Origins, Files: rd.Files})
	if err != nil {
		return nil, err
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
	if err != nil {
		return nil, fmt.Errorf("sign feed relay round: %w", err)
	}
	return &Next{ID: rd.ID.String(), Payload: pb, SignedJob: env}, nil
}

// Receive streams one file of an open round into the spool. size is the
// request's Content-Length, digest the hex SHA-256 its Content-Digest
// declared. The file is written to a temporary name, hashed, checked
// against the declaration and the round's pin, then renamed into place:
// a file that does not match never enters the spool.
func (s *Service) Receive(ctx context.Context, sn *sensor.Sensor, roundID, name string, body io.Reader, size int64, digest string) error {
	if err := s.admit(ctx, sn); err != nil {
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
	limit := min(f.MaxBytes, maxFileBytes)
	if size < 0 || size > limit || (f.Size > 0 && size != f.Size) || len(digest) != 64 {
		return ErrFileRefused
	}
	dir := s.Dir(rd.Feed)
	incoming := filepath.Join(dir, ".incoming")
	if err := os.MkdirAll(incoming, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(incoming, "up-*")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, size+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("receive feed relay file: %w", err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n != size || sum != digest || (f.SHA256 != "" && sum != f.SHA256) {
		s.logger.Warn("feed relay: file refused", "round_id", rd.ID.String(), "file", name, "bytes", n)
		return ErrFileRefused
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	keep = true
	return nil
}

// Done closes a round with the relay's report.
func (s *Service) Done(ctx context.Context, sn *sensor.Sensor, roundID string, rep dom.Report) error {
	if err := s.admit(ctx, sn); err != nil {
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

// Reconcile drives every feed one step (the controller, one replica at a
// time). It returns the rounds created.
func (s *Service) Reconcile(ctx context.Context) (int, error) {
	now := s.cfg.Now()
	if _, err := s.repo.ExpireOpen(ctx, now); err != nil {
		return 0, err
	}
	if _, err := s.repo.DeleteBefore(ctx, now.Add(-retention)); err != nil {
		s.logger.Warn("feed relay: retention", "error", err)
	}
	if !s.RelayMode(ctx) {
		return 0, nil
	}
	r, _, err := s.relay.Get(ctx)
	if err != nil {
		return 0, err
	}
	if r.SensorID == "" {
		return 0, nil // relay mode without a sensor: nothing to ask
	}
	sensorID, err := shared.IDFromString(r.SensorID)
	if err != nil {
		return 0, fmt.Errorf("feed relay sensor setting: %w", err)
	}
	created := 0
	for _, name := range s.order {
		n, err := s.step(ctx, s.feeds[name], sensorID, now)
		if err != nil {
			s.logger.Warn("feed relay: step", "feed", name, "error", err)
		}
		created += n
	}
	return created, nil
}

// step moves one feed forward: wait for an open round, back off after a
// failure, start a cycle with the head, plan after a delivered round, and
// import when nothing is missing.
func (s *Service) step(ctx context.Context, f Feed, sensorID shared.ID, now time.Time) (int, error) {
	last, err := s.repo.Latest(ctx, f.Name())
	if err != nil {
		return 0, err
	}
	backoff := min(f.Interval(), 10*time.Minute)
	switch {
	case last == nil:
		return s.create(ctx, f, sensorID, f.Head(), now)
	case last.Status == dom.StatusOpen:
		return 0, nil
	case last.Phase == dom.PhaseImported:
		if now.Sub(last.CreatedAt) < f.Interval() {
			return 0, nil
		}
		return s.create(ctx, f, sensorID, f.Head(), now)
	case last.Phase == dom.PhaseFailed, last.Status == dom.StatusRefused, last.Status == dom.StatusExpired:
		if now.Sub(last.CreatedAt) < backoff {
			return 0, nil
		}
		return s.create(ctx, f, sensorID, f.Head(), now)
	case last.Delivered() == 0:
		return 0, s.close(ctx, f, sensorID, dom.PhaseFailed, "nothing_delivered", now)
	}
	dir := s.Dir(f.Name())
	p, err := f.Plan(ctx, dir)
	if err != nil {
		code := "plan_refused"
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			code = "relay_spool_not_shared"
		}
		s.logger.Warn("feed relay: relayed files refused", "feed", f.Name(), "error", logger.SanitizeError(err))
		return 0, s.close(ctx, f, sensorID, dom.PhaseFailed, code, now)
	}
	if !p.Ready {
		return s.create(ctx, f, sensorID, p, now)
	}
	if err := f.Import(ctx, dir); err != nil {
		s.logger.Warn("feed relay: import", "feed", f.Name(), "error", logger.SanitizeError(err))
		return 0, s.close(ctx, f, sensorID, dom.PhaseFailed, "import_failed", now)
	}
	return 0, s.close(ctx, f, sensorID, dom.PhaseImported, "", now)
}

func (s *Service) create(ctx context.Context, f Feed, sensorID shared.ID, p Plan, now time.Time) (int, error) {
	if len(p.Files) == 0 {
		return 0, nil
	}
	rd := &dom.Round{ID: newID(), SensorID: sensorID, Feed: f.Name(), Phase: p.Phase, Status: dom.StatusOpen,
		Origins: f.Origins(), Files: p.Files, CreatedAt: now, ExpiresAt: now.Add(roundTTL)}
	if err := s.repo.Create(ctx, rd); err != nil {
		return 0, err
	}
	return 1, nil
}

// close writes a bookkeeping row (no files) that ends a cycle.
func (s *Service) close(ctx context.Context, f Feed, sensorID shared.ID, phase, code string, now time.Time) error {
	status := dom.StatusDone
	if phase == dom.PhaseFailed {
		status = dom.StatusFailed
	}
	return s.repo.Create(ctx, &dom.Round{ID: newID(), SensorID: sensorID, Feed: f.Name(), Phase: phase, Status: status,
		Origins: []string{}, Files: []dom.File{}, ErrorCode: code, CreatedAt: now, ExpiresAt: now, DeliveredAt: &now})
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

// FeedStatus is the console's view of one feed.
type FeedStatus struct {
	Feed       string
	Last       *dom.Round
	LastImport *dom.Round
}

// Status returns the setting, the relay sensor and each feed's latest rounds.
type Status struct {
	Settings Settings
	Sensor   *sensor.Sensor
	Feeds    []FeedStatus
}

// Status reads the console view.
func (s *Service) Status(ctx context.Context) (Status, error) {
	st, err := s.Get(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{Settings: st}
	if id, err := shared.IDFromString(st.SensorID); err == nil {
		if sn, err := s.sensors.GetByID(ctx, id); err == nil && sn != nil && sn.IsShared() {
			out.Sensor = sn
		}
	}
	for _, name := range s.order {
		fs := FeedStatus{Feed: name}
		if fs.Last, err = s.repo.Latest(ctx, name); err != nil {
			return Status{}, err
		}
		if fs.LastImport, err = s.repo.LatestOfPhase(ctx, name, dom.PhaseImported); err != nil {
			return Status{}, err
		}
		out.Feeds = append(out.Feeds, fs)
	}
	return out, nil
}
