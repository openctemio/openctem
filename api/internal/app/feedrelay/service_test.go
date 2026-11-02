package feedrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/openctem/api/internal/app/threatsource"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	dom "github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var tNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// --- fakes ---

type memSettings struct {
	mu sync.Mutex
	m  map[string]platformsetting.State
}

func (s *memSettings) Get(_ context.Context, key string) (platformsetting.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[key]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return st, nil
}

func (s *memSettings) CreateIfAbsent(_ context.Context, key string, st platformsetting.State) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; ok {
		return false, nil
	}
	s.m[key] = st
	return true, nil
}

func (s *memSettings) Update(_ context.Context, key string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[key]
	if !ok || st.Version != expected {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	st = platformsetting.State{Value: v, Version: expected + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	s.m[key] = st
	return st, nil
}

// memStore implements dom.Repository and dom.Spool in memory, with the
// claim and store rules of the Postgres repository.
type memStore struct {
	mu     sync.Mutex
	rounds []*dom.Round
	files  map[string]memFile // feed/name
	tokens map[shared.ID]shared.ID
}

type memFile struct {
	sha   string
	data  []byte
	round shared.ID
}

func newMemStore() *memStore {
	return &memStore{files: map[string]memFile{}, tokens: map[shared.ID]shared.ID{}}
}

func cloneRound(rd *dom.Round) *dom.Round { c := *rd; return &c }

func (r *memStore) Create(_ context.Context, rd *dom.Round) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rounds = append(r.rounds, cloneRound(rd))
	return nil
}

func (r *memStore) find(id shared.ID) *dom.Round {
	for _, rd := range r.rounds {
		if rd.ID == id {
			return rd
		}
	}
	return nil
}

func (r *memStore) GetForSensor(_ context.Context, id, sensorID shared.ID) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rd := r.find(id); rd != nil && rd.SensorID != nil && *rd.SensorID == sensorID {
		return cloneRound(rd), nil
	}
	return nil, dom.ErrNotFound
}

func (r *memStore) Claim(_ context.Context, rule dom.ClaimRule) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var pick *dom.Round
	for _, rd := range r.rounds {
		if rd.Status != dom.StatusOpen || !rd.ExpiresAt.After(rule.Now) {
			continue
		}
		mine := rd.SensorID != nil && *rd.SensorID == rule.SensorID
		ok := rd.SensorID == nil || mine || !slices.Contains(rule.Designated, *rd.SensorID) ||
			(rd.ClaimedAt.Before(rule.StaleBefore) && rd.DeliveredBytes == 0)
		if !ok {
			continue
		}
		if mine {
			return cloneRound(rd), nil
		}
		if pick == nil {
			pick = rd
		}
	}
	if pick == nil {
		return nil, nil
	}
	id, at := rule.SensorID, rule.Now
	pick.SensorID, pick.ClaimedAt = &id, &at
	return cloneRound(pick), nil
}

func (r *memStore) latest(feed string, ok func(*dom.Round) bool) *dom.Round {
	var out *dom.Round
	for _, rd := range r.rounds {
		if rd.Feed == feed && ok(rd) && (out == nil || !rd.CreatedAt.Before(out.CreatedAt)) {
			out = rd
		}
	}
	if out == nil {
		return nil
	}
	return cloneRound(out)
}

func (r *memStore) Latest(_ context.Context, feed string) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest(feed, func(*dom.Round) bool { return true }), nil
}

func (r *memStore) LatestOfPhase(_ context.Context, feed, phase string) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest(feed, func(rd *dom.Round) bool { return rd.Phase == phase }), nil
}

func (r *memStore) Finish(_ context.Context, id, sensorID shared.ID, status string, rep *dom.Report, at time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rd := r.find(id)
	if rd == nil || rd.Status != dom.StatusOpen || rd.SensorID == nil || *rd.SensorID != sensorID {
		return false, nil
	}
	rd.Status, rd.Report, rd.DeliveredAt = status, rep, &at
	return true, nil
}

func (r *memStore) Fail(_ context.Context, id shared.ID, code, detail string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rd := r.find(id); rd != nil && rd.Status == dom.StatusOpen {
		rd.Status, rd.ErrorCode, rd.ErrorDetail, rd.DeliveredAt = dom.StatusFailed, code, detail, &at
	}
	return nil
}

func (r *memStore) ExpireOpen(_ context.Context, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rd := range r.rounds {
		if rd.Status == dom.StatusOpen && !rd.ExpiresAt.After(now) {
			rd.Status = dom.StatusExpired
			n++
		}
	}
	return n, nil
}

func (r *memStore) DeleteBefore(context.Context, time.Time) (int, error) { return 0, nil }

func (r *memStore) Activity(_ context.Context, ids []shared.ID, _ time.Time) (map[shared.ID]dom.SensorActivity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[shared.ID]dom.SensorActivity{}
	for _, rd := range r.rounds {
		if rd.SensorID != nil && rd.DeliveredAt != nil && slices.Contains(ids, *rd.SensorID) {
			a := out[*rd.SensorID]
			a.Bytes += rd.DeliveredBytes
			a.LastDeliveredAt = rd.DeliveredAt
			out[*rd.SensorID] = a
		}
	}
	return out, nil
}

func (r *memStore) BootstrapSensor(_ context.Context, tok shared.ID) (*shared.ID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.tokens[tok]; ok {
		return &id, nil
	}
	return nil, nil
}

func (r *memStore) Store(_ context.Context, u dom.Upload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rd := r.find(u.RoundID)
	if rd == nil || rd.SensorID == nil || *rd.SensorID != u.SensorID || rd.Feed != u.Feed || rd.Status != dom.StatusOpen || !rd.ExpiresAt.After(u.Now) {
		return dom.ErrRoundClosed
	}
	key := u.Feed + "/" + u.Name
	if prev, ok := r.files[key]; ok && prev.round == u.RoundID {
		if prev.sha == u.SHA256 {
			return nil
		}
		return dom.ErrDuplicate
	}
	size := int64(len(u.Data))
	if rd.DeliveredBytes+size > u.RoundBudget {
		return dom.ErrRoundFull
	}
	var others int64
	for k, f := range r.files {
		if k != key {
			others += int64(len(f.data))
		}
	}
	if others+size > u.SpoolQuota {
		rd.ErrorCode = dom.CodeSpoolFull
		return dom.ErrSpoolFull
	}
	r.files[key] = memFile{sha: u.SHA256, data: append([]byte(nil), u.Data...), round: u.RoundID}
	rd.DeliveredBytes += size
	return nil
}

func (r *memStore) List(_ context.Context, feed string) ([]dom.SpoolFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dom.SpoolFile
	for k, f := range r.files {
		if fd, name, _ := cut(k); fd == feed {
			out = append(out, dom.SpoolFile{Name: name, SHA256: f.sha, Size: int64(len(f.data))})
		}
	}
	return out, nil
}

func cut(k string) (string, string, bool) {
	for i := range k {
		if k[i] == '/' {
			return k[:i], k[i+1:], true
		}
	}
	return k, "", false
}

func (r *memStore) Read(_ context.Context, feed, name string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.files[feed+"/"+name]
	if !ok {
		return nil, dom.ErrNotFound
	}
	return f.data, nil
}

func (r *memStore) Prune(_ context.Context, feed string, keep []string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k := range r.files {
		if fd, name, _ := cut(k); fd == feed && !slices.Contains(keep, name) {
			delete(r.files, k)
			n++
		}
	}
	return n, nil
}

func (r *memStore) Clear(context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.files)
	r.files = map[string]memFile{}
	return n, nil
}

type memSensors map[shared.ID]*sensor.Sensor

func (m memSensors) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	if s, ok := m[id]; ok {
		return s, nil
	}
	return nil, errors.New("not found")
}

type fakeSigner struct {
	mu     sync.Mutex
	got    []jobsign.Statement
	refuse *jobsign.RefusalError
}

func (f *fakeSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, st)
	if f.refuse != nil {
		return nil, fmt.Errorf("job refused: %w", f.refuse)
	}
	return json.RawMessage(`{"payloadType":"x"}`), nil
}

// fakeFeed plans from a fixed list and records imports and the directory
// it was handed.
type fakeFeed struct {
	plan    Plan
	planErr error
	imports int
	keep    []string
	dirs    []string
	seen    map[string]string // what the working directory held at Plan
}

func (f *fakeFeed) Name() string            { return dom.FeedVulnFeed }
func (f *fakeFeed) Origins() []string       { return []string{"https://feeds.example/latest/download"} }
func (f *fakeFeed) Interval() time.Duration { return 20 * time.Minute }
func (f *fakeFeed) Head() Plan {
	return Plan{Phase: dom.PhaseHead, Files: []dom.File{{Name: "keyset.dsse.json", MaxBytes: 1024}}}
}
func (f *fakeFeed) Plan(_ context.Context, dir string) (Plan, error) {
	f.dirs = append(f.dirs, dir)
	f.seen = map[string]string{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		f.seen[e.Name()] = string(b)
	}
	return f.plan, f.planErr
}
func (f *fakeFeed) Import(context.Context, string) ([]string, error) {
	f.imports++
	return f.keep, nil
}
func (f *fakeFeed) Freshness(context.Context) (Freshness, error) {
	at := tNow.Add(-time.Hour)
	return Freshness{Sequence: 7, PublishedAt: &at}, nil
}

// --- fixture ---

type fixture struct {
	svc      *Service
	store    *memStore
	signer   *fakeSigner
	relay    *sensor.Sensor
	shared2  *sensor.Sensor
	shared3  *sensor.Sensor
	noCap    *sensor.Sensor
	org      *sensor.Sensor
	sensors  memSensors
	feed     *fakeFeed
	now      time.Time
	settings *memSettings
}

func platformSensor(t *testing.T, caps ...string) *sensor.Sensor {
	t.Helper()
	seen := tNow
	s := &sensor.Sensor{ID: shared.NewID(), Name: "relay", Scope: sensor.ScopeInstance, Status: sensor.SensorStatusActive, LastSeenAt: &seen}
	s.Reported.Capabilities = caps
	return s
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: newMemStore(), signer: &fakeSigner{}, now: tNow, settings: &memSettings{m: map[string]platformsetting.State{}},
		feed: &fakeFeed{}}
	f.relay = platformSensor(t, Capability)
	f.shared2 = platformSensor(t, Capability)
	f.shared3 = platformSensor(t, Capability)
	f.noCap = platformSensor(t)
	tenant := shared.NewID()
	f.org = &sensor.Sensor{ID: shared.NewID(), Name: "org", Scope: sensor.ScopeOrganization, TenantID: &tenant, Status: sensor.SensorStatusActive}
	f.org.Reported.Capabilities = []string{Capability}
	f.sensors = memSensors{f.relay.ID: f.relay, f.shared2.ID: f.shared2, f.shared3.ID: f.shared3, f.noCap.ID: f.noCap, f.org.ID: f.org}
	f.svc = f.newService(t, t.TempDir())
	return f
}

// newService is another API replica: same database, its own working
// directory.
func (f *fixture) newService(t *testing.T, workDir string) *Service {
	t.Helper()
	svc := NewService(Config{WorkDir: workDir, Signer: f.signer, Now: func() time.Time { return f.now }},
		f.store, f.store, f.sensors, f.settings, nil, logger.NewNop())
	svc.AddFeed(f.feed)
	return svc
}

func superAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	u, err := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) designate(t *testing.T, ids ...shared.ID) {
	t.Helper()
	st, _ := f.svc.Get(context.Background())
	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}
	if _, err := f.svc.Update(context.Background(), superAdmin(t), ModeRelay, raw, st.Version, "", ""); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) relayOn(t *testing.T) { t.Helper(); f.designate(t, f.relay.ID) }

func (f *fixture) tick(t *testing.T) {
	t.Helper()
	f.now = f.now.Add(time.Second)
	if _, err := f.svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// deliver serves the next round as sn: uploads every file with the given
// bytes (or "x") and reports it.
func (f *fixture) deliver(t *testing.T, sn *sensor.Sensor, svc *Service, body map[string][]byte) string {
	t.Helper()
	ctx := context.Background()
	n, _, err := svc.Next(ctx, sn)
	if err != nil || n == nil {
		t.Fatalf("next: %v %v", n, err)
	}
	var p payload
	_ = json.Unmarshal(n.Payload, &p)
	rep := dom.Report{}
	for _, fl := range p.Files {
		b, ok := body[fl.Name]
		if !ok {
			b = []byte("x")
		}
		if err := svc.Receive(ctx, sn, n.ID, fl.Name, bytes.NewReader(b), int64(len(b)), digest(b)); err != nil {
			t.Fatalf("receive %s: %v", fl.Name, err)
		}
		rep.Files = append(rep.Files, dom.Outcome{Name: fl.Name, Status: "ok"})
	}
	if err := svc.Done(ctx, sn, n.ID, rep); err != nil {
		t.Fatal(err)
	}
	return n.ID
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func ids(ss ...*sensor.Sensor) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID.String())
	}
	return out
}

// --- tests ---

// The setting: relay needs one to three active platform sensors that report
// feed.relay@1, saved together with the mode; an organization's sensor or
// a sensor without the capability is refused at save time; a bundle
// directory or no signer locks relay mode.
func TestUpdateValidatesTheRelaySensors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for name, list := range map[string][]string{
		"organization sensor": ids(f.org),
		"no capability":       ids(f.noCap),
		"none":                nil,
		"four":                append(ids(f.relay, f.shared2, f.shared3), shared.NewID().String()),
		"not an id":           {"x"},
	} {
		if _, err := f.svc.Update(ctx, superAdmin(t), ModeRelay, list, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.Update(ctx, superAdmin(t), "proxy", nil, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad mode: %v", err)
	}
	if _, err := f.svc.Update(ctx, nil, ModeRelay, ids(f.relay), 0, "", ""); err == nil {
		t.Fatal("no actor accepted")
	}
	st, err := f.svc.Update(ctx, superAdmin(t), ModeRelay, append(ids(f.relay, f.shared2, f.shared3), f.relay.ID.String()), 0, "", "")
	if err != nil || len(st.SensorIDs) != 3 || st.Mode != ModeRelay {
		t.Fatalf("three relays (one duplicate): %+v %v", st, err)
	}
	// One write: a stale version changes neither the mode nor the list.
	if _, err := f.svc.Update(ctx, superAdmin(t), ModeDirect, nil, st.Version-1, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if got, _ := f.svc.Get(ctx); got.Mode != ModeRelay || len(got.SensorIDs) != 3 {
		t.Fatalf("after a refused write: %+v", got)
	}
	locked := NewService(Config{WorkDir: t.TempDir(), Locked: "bundle_dir", Signer: f.signer}, f.store, f.store, f.sensors,
		&memSettings{m: map[string]platformsetting.State{}}, nil, logger.NewNop())
	if _, err := locked.Update(ctx, superAdmin(t), ModeRelay, ids(f.relay), 0, "", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("bundle dir: %v", err)
	}
	unsigned := NewService(Config{WorkDir: t.TempDir()}, f.store, f.store, f.sensors,
		&memSettings{m: map[string]platformsetting.State{}}, nil, logger.NewNop())
	if _, err := unsigned.Update(ctx, superAdmin(t), ModeRelay, ids(f.relay), 0, "", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("no signer: %v", err)
	}
}

// SECURITY: only a designated, active platform sensor that reports the
// capability is offered rounds. An organization's sensor, a disabled one or
// one without the capability is refused; an eligible sensor that is not
// designated (or direct mode) gets nothing and a long Retry-After.
func TestNextOnlyForDesignatedPlatformSensors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if n, retry, err := f.svc.Next(ctx, f.relay); err != nil || n != nil || retry != RetryNotDesignated {
		t.Fatalf("direct mode: %v %v %v", n, retry, err)
	}
	f.relayOn(t)
	f.tick(t)
	disabled := *f.relay
	disabled.Status = sensor.SensorStatusDisabled
	for name, s := range map[string]*sensor.Sensor{"organization sensor": f.org, "no capability": f.noCap, "disabled": &disabled} {
		if _, _, err := f.svc.Next(ctx, s); !errors.Is(err, ErrNotRelay) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n, retry, err := f.svc.Next(ctx, f.shared2); err != nil || n != nil || retry != RetryNotDesignated {
		t.Fatalf("not designated: %v %v %v", n, retry, err)
	}
	n, _, err := f.svc.Next(ctx, f.relay)
	if err != nil || n == nil {
		t.Fatalf("designated: %v %v", n, err)
	}
	// The statement the signer gets: the platform tenant, instance scope,
	// feed_relay, the round id, the exact payload digest, origins as targets.
	st := f.signer.got[len(f.signer.got)-1]
	if st.TenantID != jobsign.PlatformTenantID || st.SensorScope != jobsign.SensorScopeInstance ||
		st.CommandType != jobsign.CommandTypeFeedRelay || st.CommandID != n.ID || st.SensorID != f.relay.ID.String() ||
		st.PayloadSHA256 != jobsign.PayloadDigest(n.Payload) || len(st.Targets) != 1 || st.Tool != "" {
		t.Fatalf("statement %+v", st)
	}
	var p payload
	if err := json.Unmarshal(n.Payload, &p); err != nil || p.Feed != dom.FeedVulnFeed || p.Targets[0] != st.Targets[0] {
		t.Fatalf("payload %s", n.Payload)
	}
	// Nothing more to claim: the sensor waits.
	if again, retry, _ := f.svc.Next(ctx, f.shared2); again != nil || retry == 0 {
		t.Fatalf("second sensor: %v %v", again, retry)
	}
}

// Failover (B2): any designated sensor claims an open round; a claim with
// nothing uploaded for ten minutes, or held by a sensor no longer
// designated, is taken over; uploads and done bind to the claimer.
func TestClaimFailover(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.designate(t, f.relay.ID, f.shared2.ID)
	f.tick(t)
	a, _, _ := f.svc.Next(ctx, f.relay)
	if a == nil {
		t.Fatal("no round")
	}
	if b, _, _ := f.svc.Next(ctx, f.shared2); b != nil {
		t.Fatal("a fresh claim was taken over")
	}
	// The claimer asks again (a restart): it gets its own round back, and
	// that does not refresh the claim.
	f.now = f.now.Add(5 * time.Minute)
	if again, _, _ := f.svc.Next(ctx, f.relay); again == nil || again.ID != a.ID {
		t.Fatal("claimer did not get its round back")
	}
	f.now = f.now.Add(5*time.Minute + time.Second)
	b, _, _ := f.svc.Next(ctx, f.shared2)
	if b == nil || b.ID != a.ID {
		t.Fatalf("stale claim not taken over: %+v", b)
	}
	body := []byte("K")
	if err := f.svc.Receive(ctx, f.relay, a.ID, "keyset.dsse.json", bytes.NewReader(body), 1, digest(body)); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("old claimer uploaded: %v", err)
	}
	if err := f.svc.Done(ctx, f.relay, a.ID, dom.Report{}); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("old claimer closed the round: %v", err)
	}
	if err := f.svc.Receive(ctx, f.shared2, b.ID, "keyset.dsse.json", bytes.NewReader(body), 1, digest(body)); err != nil {
		t.Fatal(err)
	}
	// After an upload the claim holds, even when stale...
	f.now = f.now.Add(11 * time.Minute)
	if c, _, _ := f.svc.Next(ctx, f.relay); c != nil {
		t.Fatal("a claim with uploads was taken over")
	}
	// ...unless its sensor is no longer designated.
	f.designate(t, f.relay.ID)
	if c, _, _ := f.svc.Next(ctx, f.relay); c == nil || c.ID != b.ID {
		t.Fatalf("round of an undesignated sensor not taken over: %+v", c)
	}
	if _, _, err := f.svc.Next(ctx, f.shared2); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Done(ctx, f.shared2, b.ID, dom.Report{}); !errors.Is(err, ErrNotRelay) {
		t.Fatalf("undesignated sensor closed a round: %v", err)
	}
}

// SECURITY: an upload enters the spool only when it is a file of the round
// this sensor claimed, its bytes match the declared length and digest, and
// a pinned file matches its pin. A tampered file never reaches the spool.
// One upload per file name per round (B6), within the round's budget.
func TestReceiveRefusesWhatDoesNotMatch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	good := []byte("CHUNK")
	f.feed.plan = Plan{Phase: dom.PhaseChunks, Files: []dom.File{{Name: "sha256-a.jsonl.gz", SHA256: digest(good), Size: int64(len(good)), MaxBytes: int64(len(good))}}}
	f.tick(t)
	f.deliver(t, f.relay, f.svc, nil)
	f.tick(t)
	rd, _, _ := f.svc.Next(ctx, f.relay)
	if rd == nil {
		t.Fatal("no chunk round")
	}
	bad := []byte("EVILX")
	inSpool := func() bool {
		_, err := f.store.Read(ctx, dom.FeedVulnFeed, "sha256-a.jsonl.gz")
		return err == nil
	}
	cases := []struct {
		name   string
		sensor *sensor.Sensor
		file   string
		body   []byte
		size   int64
		digest string
		want   error
	}{
		{"tampered bytes, honest digest", f.relay, "sha256-a.jsonl.gz", bad, 5, digest(bad), ErrFileRefused},
		{"digest does not match the bytes", f.relay, "sha256-a.jsonl.gz", bad, 5, digest(good), ErrFileRefused},
		{"length differs", f.relay, "sha256-a.jsonl.gz", good, 4, digest(good), ErrFileRefused},
		{"over the file cap", f.relay, "sha256-a.jsonl.gz", good, MaxFileBytes + 1, digest(good), ErrFileRefused},
		{"name not in the round", f.relay, "other.json", good, 5, digest(good), ErrFileRefused},
		{"path traversal", f.relay, "../sha256-a.jsonl.gz", good, 5, digest(good), ErrFileRefused},
		{"organization sensor", f.org, "sha256-a.jsonl.gz", good, 5, digest(good), ErrNotRelay},
		{"other platform sensor", f.shared2, "sha256-a.jsonl.gz", good, 5, digest(good), ErrNotRelay},
	}
	for _, tc := range cases {
		err := f.svc.Receive(ctx, tc.sensor, rd.ID, tc.file, bytes.NewReader(tc.body), tc.size, tc.digest)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if inSpool() {
			t.Fatalf("%s: a refused file reached the spool", tc.name)
		}
	}
	if err := f.svc.Receive(ctx, f.relay, rd.ID, "sha256-a.jsonl.gz", bytes.NewReader(good), 5, digest(good)); err != nil {
		t.Fatalf("the pinned file: %v", err)
	}
	if b, _ := f.store.Read(ctx, dom.FeedVulnFeed, "sha256-a.jsonl.gz"); string(b) != "CHUNK" {
		t.Fatalf("spool holds %q", b)
	}
	// The same file again (a retried upload) is accepted and not counted
	// twice.
	if err := f.svc.Receive(ctx, f.relay, rd.ID, "sha256-a.jsonl.gz", bytes.NewReader(good), 5, digest(good)); err != nil {
		t.Fatalf("retried upload: %v", err)
	}
	if r := f.store.find(mustID(t, rd.ID)); r.DeliveredBytes != 5 {
		t.Fatalf("delivered bytes %d", r.DeliveredBytes)
	}
	// A closed round takes nothing more.
	if err := f.svc.Done(ctx, f.relay, rd.ID, dom.Report{}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Receive(ctx, f.relay, rd.ID, "sha256-a.jsonl.gz", bytes.NewReader(good), 5, digest(good)); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("closed round: %v", err)
	}
	if err := f.svc.Done(ctx, f.relay, rd.ID, dom.Report{}); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("done twice: %v", err)
	}
}

func mustID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// B6: an unpinned file uploaded twice in one round with other bytes is
// refused; the round's budget and the spool quota are enforced in the
// store (memStore mirrors the SQL; the DB test covers the real one).
func TestReceiveOneUploadPerName(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	n, _, _ := f.svc.Next(ctx, f.relay)
	one, two := []byte("A"), []byte("B")
	if err := f.svc.Receive(ctx, f.relay, n.ID, "keyset.dsse.json", bytes.NewReader(one), 1, digest(one)); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Receive(ctx, f.relay, n.ID, "keyset.dsse.json", bytes.NewReader(two), 1, digest(two)); !errors.Is(err, ErrFileRefused) {
		t.Fatalf("second upload with other bytes: %v", err)
	}
	if b, _ := f.store.Read(ctx, dom.FeedVulnFeed, "keyset.dsse.json"); string(b) != "A" {
		t.Fatalf("spool holds %q", b)
	}
}

// B3: a round the job signer refuses is closed failed with signer_refused
// and the reason (shown in the console), the sensor gets an empty answer,
// and the next cycle waits for the back-off instead of looping.
func TestSignerRefusalIsVisible(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	f.signer.refuse = &jobsign.RefusalError{Status: 403, Reason: "feed_relay_origin", Detail: "target 0 is not in the signer's feed origin allowlist (SIGNER_FEED_ORIGINS)<script>"}
	n, retry, err := f.svc.Next(ctx, f.relay)
	if err != nil || n != nil || retry != RetryIdle {
		t.Fatalf("refused round: %v %v %v", n, retry, err)
	}
	last, _ := f.store.Latest(ctx, dom.FeedVulnFeed)
	if last.Status != dom.StatusFailed || last.ErrorCode != dom.CodeSignerRefused ||
		last.ErrorDetail != "feed_relay_origin: target 0 is not in the signer's feed origin allowlist (SIGNER_FEED_ORIGINS)script" {
		t.Fatalf("round %+v", last)
	}
	st, _ := f.svc.Status(ctx)
	if st.Feeds[0].StaleReason != dom.CodeSignerRefused || st.Feeds[0].Detail == "" {
		t.Fatalf("status %+v", st.Feeds[0])
	}
	f.tick(t)
	if again, _ := f.store.Latest(ctx, dom.FeedVulnFeed); again.ID != last.ID {
		t.Fatal("no back-off after a signer refusal")
	}
	f.signer.refuse = nil
	f.now = f.now.Add(11 * time.Minute)
	f.tick(t)
	if n, _, _ := f.svc.Next(ctx, f.relay); n == nil {
		t.Fatal("no new cycle after the back-off")
	}
}

// B4: why relayed files did not plan or import is named from the error and
// the relay's report, never as a shared-storage problem.
func TestFailureCode(t *testing.T) {
	notFound := &dom.Round{Report: &dom.Report{Files: []dom.Outcome{{Name: "a", Status: "not_found", Code: "not_found"}}}}
	for name, tc := range map[string]struct {
		err  error
		last *dom.Round
		want string
	}{
		"rollback":           {fmt.Errorf("pointer: %w", bundle.ErrRollback), nil, dom.CodeRollbackRefused},
		"pin":                {fmt.Errorf("manifest: %w", bundle.ErrPinMismatch), nil, dom.CodePinMismatch},
		"signature":          {fmt.Errorf("key set: %w: x", bundle.ErrSignature), nil, dom.CodeVerifyFailed},
		"missing, 404":       {fmt.Errorf("pointer: %w", os.ErrNotExist), notFound, dom.CodeUpstreamMissing},
		"missing, not a 404": {fmt.Errorf("pointer: %w", os.ErrNotExist), &dom.Round{}, dom.CodeNothingDelivered},
		"other":              {errors.New("db"), nil, dom.CodePlanFailed},
	} {
		if got := failureCode(tc.err, tc.last, dom.CodePlanFailed); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

// The cycle: head, then planned rounds, then the import once nothing is
// missing, then a pause until the next cycle; a refused plan and a round
// that delivered nothing back off instead of looping. Import prunes the
// spool to what the release still needs.
func TestReconcileCycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	if n, _ := f.svc.Reconcile(ctx); n != 0 {
		t.Fatal("a second round while one is open")
	}
	f.deliver(t, f.relay, f.svc, map[string][]byte{"keyset.dsse.json": []byte("KS")})
	if retry := f.svc.idleRetry(ctx); retry != RetryInCycle {
		t.Fatalf("in-cycle retry %v", retry)
	}
	f.feed.plan = Plan{Ready: true}
	f.feed.keep = []string{}
	f.tick(t)
	if f.feed.imports != 1 || f.feed.seen["keyset.dsse.json"] != "KS" {
		t.Fatalf("imports %d, saw %v", f.feed.imports, f.feed.seen)
	}
	if left, _ := f.store.List(ctx, dom.FeedVulnFeed); len(left) != 0 {
		t.Fatalf("not pruned: %v", left)
	}
	if _, err := os.Stat(filepath.Join(f.svc.Dir(dom.FeedVulnFeed), "keyset.dsse.json")); err == nil {
		t.Fatal("pruned file left in the working directory")
	}
	f.tick(t)
	if f.feed.imports != 1 || len(f.store.rounds) != 2 {
		t.Fatalf("imported again inside the interval: %d rounds", len(f.store.rounds))
	}
	f.now = f.now.Add(21 * time.Minute)
	f.tick(t)
	last, _ := f.store.Latest(ctx, dom.FeedVulnFeed)
	if last.Phase != dom.PhaseHead || last.Status != dom.StatusOpen {
		t.Fatalf("next cycle: %+v", last)
	}
	// A head the planner refuses (a relay or publisher serving what the
	// pinned root did not sign) fails the cycle and backs off.
	f.deliver(t, f.relay, f.svc, nil)
	f.feed.planErr = fmt.Errorf("key set: %w: bad", bundle.ErrSignature)
	f.tick(t)
	last, _ = f.store.Latest(ctx, dom.FeedVulnFeed)
	if last.Phase != dom.PhaseFailed || last.ErrorCode != dom.CodeVerifyFailed {
		t.Fatalf("refused plan: %+v", last)
	}
	f.tick(t)
	if again, _ := f.store.Latest(ctx, dom.FeedVulnFeed); again.ID != last.ID {
		t.Fatal("no back-off after a refused plan")
	}
	// A round that delivered nothing ends the cycle (no tight loop).
	f.feed.planErr = nil
	f.now = f.now.Add(11 * time.Minute)
	f.tick(t)
	n, _, _ := f.svc.Next(ctx, f.relay)
	_ = f.svc.Done(ctx, f.relay, n.ID, dom.Report{Files: []dom.Outcome{{Name: "keyset.dsse.json", Status: "not_found", Code: "not_found"}}})
	f.tick(t)
	last, _ = f.store.Latest(ctx, dom.FeedVulnFeed)
	if last.ErrorCode != dom.CodeUpstreamMissing {
		t.Fatalf("nothing delivered: %+v", last)
	}
}

// Two API replicas (B1): uploads land through one, the replica holding the
// controller lease plans and imports from its own working directory, which
// it fills from the shared spool; a file changed in the spool is rewritten
// locally and a removed one is deleted.
func TestTwoReplicasShareTheSpool(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	other := f.newService(t, t.TempDir()) // receives the uploads
	f.tick(t)
	f.deliver(t, f.relay, other, map[string][]byte{"keyset.dsse.json": []byte("ONE")})
	f.feed.plan = Plan{Phase: dom.PhaseManifests, Files: []dom.File{{Name: "pointer.dsse.json", MaxBytes: 64}}}
	f.tick(t)
	if f.feed.seen["keyset.dsse.json"] != "ONE" || f.feed.dirs[0] != f.svc.Dir(dom.FeedVulnFeed) {
		t.Fatalf("lease holder saw %v in %v", f.feed.seen, f.feed.dirs)
	}
	f.deliver(t, f.relay, other, map[string][]byte{"pointer.dsse.json": []byte("P")})
	f.tick(t)
	if f.feed.seen["pointer.dsse.json"] != "P" || f.feed.seen["keyset.dsse.json"] != "ONE" {
		t.Fatalf("second plan saw %v", f.feed.seen)
	}
	// A spool row changes (a new cycle's head) and another goes away.
	f.store.mu.Lock()
	f.store.files["vulnfeed/keyset.dsse.json"] = memFile{sha: digest([]byte("TWO")), data: []byte("TWO")}
	delete(f.store.files, "vulnfeed/pointer.dsse.json")
	f.store.mu.Unlock()
	if _, err := f.svc.materialize(ctx, dom.FeedVulnFeed); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(f.svc.Dir(dom.FeedVulnFeed), "keyset.dsse.json"))
	if string(b) != "TWO" {
		t.Fatalf("working copy not refreshed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(f.svc.Dir(dom.FeedVulnFeed), "pointer.dsse.json")); err == nil {
		t.Fatal("removed spool file left in the working directory")
	}
	// A spool row whose bytes do not match its digest is never copied.
	f.store.mu.Lock()
	f.store.files["vulnfeed/keyset.dsse.json"] = memFile{sha: digest([]byte("TWO")), data: []byte("EVL")}
	f.store.mu.Unlock()
	fresh := f.newService(t, t.TempDir())
	if _, err := fresh.materialize(ctx, dom.FeedVulnFeed); err == nil {
		t.Fatal("a spool row that does not match its digest was copied")
	}
	if _, err := os.Stat(filepath.Join(fresh.Dir(dom.FeedVulnFeed), "keyset.dsse.json")); err == nil {
		t.Fatal("tampered row reached the working directory")
	}
}

// An expired round is closed, never offered again, and a new cycle starts.
func TestExpiredRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	first, _, _ := f.svc.Next(ctx, f.relay)
	f.now = f.now.Add(roundTTL + time.Second)
	if n, _, _ := f.svc.Next(ctx, f.relay); n != nil {
		t.Fatal("an expired round was offered")
	}
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	n, _, _ := f.svc.Next(ctx, f.relay)
	if n == nil || n.ID == first.ID {
		t.Fatalf("no new cycle: %+v", n)
	}
	statuses := []string{}
	for _, rd := range f.store.rounds {
		statuses = append(statuses, rd.Status)
	}
	sort.Strings(statuses)
	if len(statuses) != 2 || statuses[0] != dom.StatusExpired || statuses[1] != dom.StatusOpen {
		t.Fatalf("statuses %v", statuses)
	}
	if err := f.svc.Done(ctx, f.relay, first.ID, dom.Report{}); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("expired round closed again: %v", err)
	}
}

// A new install (owner decision 3): the install stores relay mode with the
// bundled sensor's token, only when the setting was never written; the
// sensor that enrolled with that token is designated once it reports
// feed.relay@1, and no other sensor is.
func TestBootstrapDesignatesTheBundledSensor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tok := shared.NewID()
	if ok, err := SeedRelayMode(ctx, f.settings, tok); err != nil || !ok {
		t.Fatalf("seed: %v %v", ok, err)
	}
	if ok, _ := SeedRelayMode(ctx, f.settings, shared.NewID()); ok {
		t.Fatal("seeded twice")
	}
	svc := f.newService(t, t.TempDir()) // fresh cache: reads the seeded row
	if !svc.RelayMode(ctx) {
		t.Fatal("not in relay mode")
	}
	st, _ := svc.Status(ctx)
	if st.Feeds[0].StaleReason != dom.CodeNoRelayDesignated || !st.Settings.Bootstrap {
		t.Fatalf("before enrollment: %+v", st)
	}
	// The bundled sensor enrolled but does not report the capability yet.
	bundled := platformSensor(t)
	f.sensors[bundled.ID] = bundled
	f.store.tokens[tok] = bundled.ID
	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Get(ctx); len(got.SensorIDs) != 0 {
		t.Fatalf("designated without the capability: %+v", got)
	}
	bundled.Reported.Capabilities = []string{Capability}
	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.Get(ctx)
	if len(got.SensorIDs) != 1 || got.SensorIDs[0] != bundled.ID.String() || got.Bootstrap || got.Mode != ModeRelay {
		t.Fatalf("after enrollment: %+v", got)
	}
	if n, _, _ := svc.Next(ctx, bundled); n == nil {
		t.Fatal("bundled sensor gets no round")
	}
	if n, retry, _ := svc.Next(ctx, f.relay); n != nil || retry != RetryNotDesignated {
		t.Fatal("another platform sensor was offered a round")
	}
	// An existing install (the migration wrote direct) is never switched.
	existing := &memSettings{m: map[string]platformsetting.State{ModeKey: {Value: json.RawMessage(`{"mode":"direct"}`), Version: 1}}}
	if ok, _ := SeedRelayMode(ctx, existing, tok); ok {
		t.Fatal("an existing install was switched to relay mode")
	}
}

// Never an automatic fallback to direct: a setting that cannot be read
// counts as relay mode (no outbound feed request).
func TestRelayModeFailsClosed(t *testing.T) {
	f := newFixture(t)
	svc := NewService(Config{WorkDir: t.TempDir(), Signer: f.signer}, f.store, f.store, f.sensors, brokenSettings{&memSettings{}}, nil, logger.NewNop())
	if !svc.RelayMode(context.Background()) {
		t.Fatal("an unreadable setting fell back to direct")
	}
}

type brokenSettings struct{ *memSettings }

func (brokenSettings) Get(context.Context, string) (platformsetting.State, error) {
	return platformsetting.State{}, errors.New("db down")
}

// Status: the feed's age, the cycle in progress with its progress and
// claimer, the relay sensors and why a feed is stale.
func TestStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.designate(t, f.relay.ID, f.shared2.ID)
	f.tick(t)
	n, _, _ := f.svc.Next(ctx, f.relay)
	b := []byte("KS")
	_ = f.svc.Receive(ctx, f.relay, n.ID, "keyset.dsse.json", bytes.NewReader(b), 2, digest(b))
	st, err := f.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fs := st.Feeds[0]
	if fs.Current == nil || fs.Current.DeliveredBytes != 2 || fs.Current.SensorID == nil || *fs.Current.SensorID != f.relay.ID ||
		fs.Freshness.Sequence != 7 || fs.Freshness.PublishedAt == nil || fs.StaleReason != "" || len(st.Sensors) != 2 || !st.Sensors[0].Online {
		t.Fatalf("status %+v / %+v", st, fs)
	}
	// Both relays offline.
	old := f.now.Add(-time.Hour)
	f.relay.LastSeenAt, f.shared2.LastSeenAt = &old, &old
	st, _ = f.svc.Status(ctx)
	if st.Feeds[0].StaleReason != dom.CodeRelayOffline {
		t.Fatalf("offline: %+v", st.Feeds[0])
	}
	for _, tc := range []struct {
		last *dom.Round
		want string
	}{
		{&dom.Round{Status: dom.StatusRefused, Report: &dom.Report{Refused: "signature_bad"}}, dom.CodeSensorRefused},
		{&dom.Round{Status: dom.StatusExpired}, dom.CodeRoundExpired},
		{&dom.Round{Status: dom.StatusFailed, ErrorCode: dom.CodePinMismatch}, dom.CodePinMismatch},
		{&dom.Round{Status: dom.StatusOpen, ErrorCode: dom.CodeSpoolFull}, dom.CodeSpoolFull},
		{&dom.Round{Status: dom.StatusDone, Phase: dom.PhaseImported}, ""},
	} {
		if got, _ := staleReason(true, true, tc.last); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.last, got, tc.want)
		}
	}
}

// The spool is emptied after seven days in direct mode, not before.
func TestSpoolClearedAfterDirectMode(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	f.tick(t)
	f.deliver(t, f.relay, f.svc, nil)
	st, _ := f.svc.Get(ctx)
	if _, err := f.svc.Update(ctx, superAdmin(t), ModeDirect, nil, st.Version, "", ""); err != nil {
		t.Fatal(err)
	}
	f.tick(t)
	if left, _ := f.store.List(ctx, dom.FeedVulnFeed); len(left) == 0 {
		t.Fatal("cleared at once")
	}
	f.now = f.now.Add(clearAfter + time.Minute)
	f.settings.mu.Lock()
	s := f.settings.m[ModeKey]
	s.UpdatedAt = tNow
	f.settings.m[ModeKey] = s
	f.settings.mu.Unlock()
	svc := f.newService(t, t.TempDir())
	if _, err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if left, _ := f.store.List(ctx, dom.FeedVulnFeed); len(left) != 0 {
		t.Fatalf("not cleared: %v", left)
	}
}

// The relay's report is kept only for the round's own files, with bounded
// codes (never free text).
func TestDoneSanitizesTheReport(t *testing.T) {
	rd := &dom.Round{Files: []dom.File{{Name: "a"}}}
	out := sanitize(dom.Report{Refused: "Signature <b>bad</b>", Files: []dom.Outcome{
		{Name: "a", Status: "ok", Code: "x y\nz"}, {Name: "a", Status: "ok"}, {Name: "evil", Status: "ok"},
	}}, rd)
	if len(out.Files) != 1 || out.Files[0].Code != "xyz" || out.Refused != "ignaturebbadb" {
		t.Fatalf("%+v", out)
	}
}

// ZERO EGRESS: in relay mode the KEV/EPSS policy never allows the direct
// fetch, whatever the stored threat intel source says.
func TestThreatSourcePolicyInRelayMode(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := ThreatSourcePolicy{Inner: staticPolicy{threatsource.Policy{DirectAllowed: true}}, Relay: f.svc}
	if got, _ := p.Policy(ctx); !got.DirectAllowed {
		t.Fatal("direct mode must keep the stored policy")
	}
	f.relayOn(t)
	if got, _ := p.Policy(ctx); got.DirectAllowed || !got.PreferBundle {
		t.Fatalf("relay mode: %+v", got)
	}
}

type staticPolicy struct{ p threatsource.Policy }

func (s staticPolicy) Policy(context.Context) (threatsource.Policy, error) { return s.p, nil }
