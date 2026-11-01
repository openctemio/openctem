package feedrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

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

type memRounds struct {
	mu     sync.Mutex
	rounds []*dom.Round
}

func (r *memRounds) Create(_ context.Context, rd *dom.Round) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := *rd
	r.rounds = append(r.rounds, &c)
	return nil
}

func (r *memRounds) GetForSensor(_ context.Context, id, sensorID shared.ID) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range r.rounds {
		if rd.ID == id && rd.SensorID == sensorID {
			c := *rd
			return &c, nil
		}
	}
	return nil, dom.ErrNotFound
}

func (r *memRounds) NextOpen(_ context.Context, sensorID shared.ID, now time.Time) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range r.rounds {
		if rd.SensorID == sensorID && rd.Status == dom.StatusOpen && now.Before(rd.ExpiresAt) {
			c := *rd
			return &c, nil
		}
	}
	return nil, nil
}

func (r *memRounds) latest(feed string, ok func(*dom.Round) bool) *dom.Round {
	var out *dom.Round
	for _, rd := range r.rounds {
		if rd.Feed == feed && ok(rd) && (out == nil || !rd.CreatedAt.Before(out.CreatedAt)) {
			out = rd
		}
	}
	if out == nil {
		return nil
	}
	c := *out
	return &c
}

func (r *memRounds) Latest(_ context.Context, feed string) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest(feed, func(*dom.Round) bool { return true }), nil
}

func (r *memRounds) LatestOfPhase(_ context.Context, feed, phase string) (*dom.Round, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest(feed, func(rd *dom.Round) bool { return rd.Phase == phase }), nil
}

func (r *memRounds) Finish(_ context.Context, id, sensorID shared.ID, status string, rep *dom.Report, at time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range r.rounds {
		if rd.ID == id && rd.SensorID == sensorID && rd.Status == dom.StatusOpen {
			rd.Status, rd.Report, rd.DeliveredAt = status, rep, &at
			return true, nil
		}
	}
	return false, nil
}

func (r *memRounds) ExpireOpen(_ context.Context, now time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rd := range r.rounds {
		if rd.Status == dom.StatusOpen && !now.Before(rd.ExpiresAt) {
			rd.Status = dom.StatusExpired
			n++
		}
	}
	return n, nil
}

func (r *memRounds) DeleteBefore(context.Context, time.Time) (int, error) { return 0, nil }

type memSensors map[shared.ID]*sensor.Sensor

func (m memSensors) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	if s, ok := m[id]; ok {
		return s, nil
	}
	return nil, errors.New("not found")
}

type fakeSigner struct {
	mu  sync.Mutex
	got []jobsign.Statement
}

func (f *fakeSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, st)
	return json.RawMessage(`{"payloadType":"x"}`), nil
}

// fakeFeed plans from a fixed list and records imports.
type fakeFeed struct {
	plan    Plan
	planErr error
	imports int
}

func (f *fakeFeed) Name() string            { return dom.FeedVulnFeed }
func (f *fakeFeed) Origins() []string       { return []string{"https://feeds.example/latest/download"} }
func (f *fakeFeed) Interval() time.Duration { return 20 * time.Minute }
func (f *fakeFeed) Head() Plan {
	return Plan{Phase: dom.PhaseHead, Files: []dom.File{{Name: "keyset.dsse.json", MaxBytes: 1024}}}
}
func (f *fakeFeed) Plan(context.Context, string) (Plan, error) { return f.plan, f.planErr }
func (f *fakeFeed) Import(context.Context, string) error {
	f.imports++
	return nil
}

// --- fixture ---

type fixture struct {
	svc      *Service
	rounds   *memRounds
	signer   *fakeSigner
	relay    *sensor.Sensor
	shared2  *sensor.Sensor
	org      *sensor.Sensor
	feed     *fakeFeed
	now      time.Time
	settings *memSettings
}

func platformSensor(t *testing.T, caps ...string) *sensor.Sensor {
	t.Helper()
	s := &sensor.Sensor{ID: shared.NewID(), Name: "relay", Scope: sensor.ScopeInstance, Status: sensor.SensorStatusActive}
	s.Reported.Capabilities = caps
	return s
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{rounds: &memRounds{}, signer: &fakeSigner{}, now: tNow, settings: &memSettings{m: map[string]platformsetting.State{}},
		feed: &fakeFeed{}}
	f.relay = platformSensor(t, Capability)
	f.shared2 = platformSensor(t, Capability)
	tenant := shared.NewID()
	f.org = &sensor.Sensor{ID: shared.NewID(), Name: "org", Scope: sensor.ScopeOrganization, TenantID: &tenant, Status: sensor.SensorStatusActive}
	f.org.Reported.Capabilities = []string{Capability}
	sensors := memSensors{f.relay.ID: f.relay, f.shared2.ID: f.shared2, f.org.ID: f.org}
	f.svc = NewService(Config{Spool: t.TempDir(), Signer: f.signer, Now: func() time.Time { return f.now }},
		f.rounds, sensors, f.settings, nil, logger.NewNop())
	f.svc.AddFeed(f.feed)
	return f
}

func superAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	u, err := admin.NewAdminUser("root@example.com", "Root", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) relayOn(t *testing.T) {
	t.Helper()
	if _, err := f.svc.Update(context.Background(), superAdmin(t), ModeRelay, f.relay.ID.String(), 0, "", ""); err != nil {
		t.Fatal(err)
	}
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// --- tests ---

// The setting: relay needs an active platform sensor; an organization's
// sensor is never accepted; a bundle directory or no signer locks it.
func TestUpdateValidatesTheRelaySensor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Update(ctx, superAdmin(t), ModeRelay, f.org.ID.String(), 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("organization sensor: %v", err)
	}
	if _, err := f.svc.Update(ctx, superAdmin(t), ModeRelay, "", 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no sensor: %v", err)
	}
	if _, err := f.svc.Update(ctx, superAdmin(t), "proxy", "", 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad mode: %v", err)
	}
	if _, err := f.svc.Update(ctx, nil, ModeRelay, f.relay.ID.String(), 0, "", ""); err == nil {
		t.Fatal("no actor accepted")
	}
	f.relayOn(t)
	if !f.svc.RelayMode(ctx) {
		t.Fatal("relay mode not on")
	}
	locked := NewService(Config{Spool: t.TempDir(), Locked: "bundle_dir", Signer: f.signer}, f.rounds, memSensors{f.relay.ID: f.relay},
		&memSettings{m: map[string]platformsetting.State{}}, nil, logger.NewNop())
	if _, err := locked.Update(ctx, superAdmin(t), ModeRelay, f.relay.ID.String(), 0, "", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("bundle dir: %v", err)
	}
	unsigned := NewService(Config{Spool: t.TempDir()}, f.rounds, memSensors{f.relay.ID: f.relay},
		&memSettings{m: map[string]platformsetting.State{}}, nil, logger.NewNop())
	if _, err := unsigned.Update(ctx, superAdmin(t), ModeRelay, f.relay.ID.String(), 0, "", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("no signer: %v", err)
	}
}

// SECURITY: only the designated, active platform sensor that reports the
// capability is offered rounds; an organization's sensor, another platform
// sensor and the designated one in direct mode are refused alike.
func TestNextOnlyForTheDesignatedPlatformSensor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Next(ctx, f.relay); !errors.Is(err, ErrNotRelay) {
		t.Fatalf("direct mode: %v", err)
	}
	f.relayOn(t)
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*sensor.Sensor{"organization sensor": f.org, "other platform sensor": f.shared2} {
		if _, err := f.svc.Next(ctx, s); !errors.Is(err, ErrNotRelay) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noCap := *f.relay
	noCap.Reported.Capabilities = nil
	if _, err := f.svc.Next(ctx, &noCap); !errors.Is(err, ErrNotRelay) {
		t.Errorf("without the capability: %v", err)
	}
	disabled := *f.relay
	disabled.Status = sensor.SensorStatusDisabled
	if _, err := f.svc.Next(ctx, &disabled); !errors.Is(err, ErrNotRelay) {
		t.Errorf("disabled: %v", err)
	}
	n, err := f.svc.Next(ctx, f.relay)
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
}

// SECURITY: an upload enters the spool only when it is a file of this
// sensor's open round, its bytes match the declared length and digest, and
// a pinned file matches its pin. A tampered file never reaches the spool.
func TestReceiveRefusesWhatDoesNotMatch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	good := []byte("CHUNK")
	f.feed.plan = Plan{Phase: dom.PhaseChunks, Files: []dom.File{{Name: "sha256-a.jsonl.gz", SHA256: digest(good), Size: int64(len(good)), MaxBytes: int64(len(good))}}}
	// Head round delivered, then the chunk round.
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	head, _ := f.svc.Next(ctx, f.relay)
	if err := f.svc.Receive(ctx, f.relay, head.ID, "keyset.dsse.json", bytes.NewReader([]byte("K")), 1, digest([]byte("K"))); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Done(ctx, f.relay, head.ID, dom.Report{Files: []dom.Outcome{{Name: "keyset.dsse.json", Status: "ok"}}}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	rd, _ := f.svc.Next(ctx, f.relay)
	if rd == nil || rd.ID == head.ID {
		t.Fatalf("no chunk round: %+v", rd)
	}
	bad := []byte("EVILX")
	spool := filepath.Join(f.svc.Dir(dom.FeedVulnFeed), "sha256-a.jsonl.gz")
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
		if _, err := os.Stat(spool); err == nil {
			t.Fatalf("%s: a refused file reached the spool", tc.name)
		}
	}
	if err := f.svc.Receive(ctx, f.relay, rd.ID, "sha256-a.jsonl.gz", bytes.NewReader(good), 5, digest(good)); err != nil {
		t.Fatalf("the pinned file: %v", err)
	}
	if b, _ := os.ReadFile(spool); string(b) != "CHUNK" {
		t.Fatalf("spool holds %q", b)
	}
	// A closed or expired round takes nothing more.
	if err := f.svc.Done(ctx, f.relay, rd.ID, dom.Report{}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Receive(ctx, f.relay, rd.ID, "sha256-a.jsonl.gz", bytes.NewReader(good), 5, digest(good)); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("closed round: %v", err)
	}
	if err := f.svc.Done(ctx, f.relay, rd.ID, dom.Report{}); !errors.Is(err, ErrRoundClosed) {
		t.Fatalf("done twice: %v", err)
	}
	// Nothing is left behind in the temporary directory.
	left, _ := os.ReadDir(filepath.Join(f.svc.Dir(dom.FeedVulnFeed), ".incoming"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %d", len(left))
	}
}

// The cycle: head, then planned rounds, then the import once nothing is
// missing, then a pause until the next cycle; a refused plan and a round
// that delivered nothing back off instead of looping.
func TestReconcileCycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	deliver := func() {
		t.Helper()
		n, err := f.svc.Next(ctx, f.relay)
		if err != nil || n == nil {
			t.Fatalf("next: %v %v", n, err)
		}
		var p payload
		_ = json.Unmarshal(n.Payload, &p)
		rep := dom.Report{}
		for _, fl := range p.Files {
			rep.Files = append(rep.Files, dom.Outcome{Name: fl.Name, Status: "ok"})
		}
		if err := f.svc.Done(ctx, f.relay, n.ID, rep); err != nil {
			t.Fatal(err)
		}
	}
	tick := func() {
		t.Helper()
		f.now = f.now.Add(time.Second)
		if _, err := f.svc.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	tick()
	if n, _ := f.svc.Reconcile(ctx); n != 0 {
		t.Fatal("a second round while one is open")
	}
	deliver()
	f.feed.plan = Plan{Ready: true}
	tick()
	if f.feed.imports != 1 {
		t.Fatalf("imports %d", f.feed.imports)
	}
	tick()
	if f.feed.imports != 1 || len(f.rounds.rounds) != 2 {
		t.Fatalf("imported again inside the interval: %d rounds", len(f.rounds.rounds))
	}
	f.now = f.now.Add(21 * time.Minute)
	tick()
	last, _ := f.rounds.Latest(ctx, dom.FeedVulnFeed)
	if last.Phase != dom.PhaseHead || last.Status != dom.StatusOpen {
		t.Fatalf("next cycle: %+v", last)
	}
	// A head the planner refuses (a relay or publisher serving what the
	// pinned root did not sign) fails the cycle and backs off.
	deliver()
	f.feed.planErr = errors.New("key set: signature")
	tick()
	last, _ = f.rounds.Latest(ctx, dom.FeedVulnFeed)
	if last.Phase != dom.PhaseFailed || last.ErrorCode != "plan_refused" {
		t.Fatalf("refused plan: %+v", last)
	}
	tick()
	if again, _ := f.rounds.Latest(ctx, dom.FeedVulnFeed); again.ID != last.ID {
		t.Fatal("no back-off after a refused plan")
	}
	// A round that delivered nothing ends the cycle (no tight loop).
	f.feed.planErr = nil
	f.now = f.now.Add(11 * time.Minute)
	tick()
	n, _ := f.svc.Next(ctx, f.relay)
	_ = f.svc.Done(ctx, f.relay, n.ID, dom.Report{Files: []dom.Outcome{{Name: "keyset.dsse.json", Status: "not_found"}}})
	tick()
	last, _ = f.rounds.Latest(ctx, dom.FeedVulnFeed)
	if last.ErrorCode != "nothing_delivered" {
		t.Fatalf("nothing delivered: %+v", last)
	}
}

// An expired round is closed, never offered again, and a new cycle starts
// (its back-off has passed: the round lived longer than it).
func TestExpiredRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.relayOn(t)
	_, _ = f.svc.Reconcile(ctx)
	first, _ := f.svc.Next(ctx, f.relay)
	f.now = f.now.Add(roundTTL + time.Second)
	if n, _ := f.svc.Next(ctx, f.relay); n != nil {
		t.Fatal("an expired round was offered")
	}
	_, _ = f.svc.Reconcile(ctx)
	n, _ := f.svc.Next(ctx, f.relay)
	if n == nil || n.ID == first.ID {
		t.Fatalf("no new cycle: %+v", n)
	}
	statuses := []string{}
	for _, rd := range f.rounds.rounds {
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
