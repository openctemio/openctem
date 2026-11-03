package subscription

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/licensekey"
	lkt "github.com/openctemio/openctem/api/pkg/licensekey/licensekeytest"
)

const installID = "7f3c2a10-1111-4222-8333-944455556666"

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// memRepo is an in-memory Repository with the same semantics as the
// Postgres one.
type memRepo struct {
	mu      sync.Mutex
	state   State
	recs    []Record
	failAll error
}

func newMemRepo() *memRepo {
	return &memRepo{state: State{InstallationID: installID, TimeHighWater: t0.Add(-time.Hour), Version: 1}}
}

func (m *memRepo) State(context.Context) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAll != nil {
		return State{}, m.failAll
	}
	st := m.state
	st.Revoked = licensekey.Revocations{LicenseIDs: slices.Clone(st.Revoked.LicenseIDs), KeyIDs: slices.Clone(st.Revoked.KeyIDs)}
	return st, nil
}

func (m *memRepo) Version(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAll != nil {
		return 0, m.failAll
	}
	return m.state.Version, nil
}

func (m *memRepo) List(_ context.Context, limit int) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAll != nil {
		return nil, m.failAll
	}
	out := slices.Clone(m.recs)
	slices.Reverse(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memRepo) Add(_ context.Context, rec Record, ks uint64, revoked licensekey.Revocations) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recs {
		if r.LicenseID == rec.LicenseID && r.RemovedAt == nil {
			return ErrAlreadyStored
		}
	}
	m.recs = append(m.recs, rec)
	m.state.KeySetHighWater = max(m.state.KeySetHighWater, ks)
	for _, id := range revoked.LicenseIDs {
		if !slices.Contains(m.state.Revoked.LicenseIDs, id) {
			m.state.Revoked.LicenseIDs = append(m.state.Revoked.LicenseIDs, id)
		}
	}
	for _, id := range revoked.KeyIDs {
		if !slices.Contains(m.state.Revoked.KeyIDs, id) {
			m.state.Revoked.KeyIDs = append(m.state.Revoked.KeyIDs, id)
		}
	}
	m.state.Version++
	return nil
}

func (m *memRepo) Remove(_ context.Context, id shared.ID, by *shared.ID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.recs {
		if m.recs[i].ID == id && m.recs[i].RemovedAt == nil {
			m.recs[i].RemovedAt, m.recs[i].RemovedBy = &at, by
			m.state.Version++
			return nil
		}
	}
	return ErrNotFound
}

func (m *memRepo) AdvanceTimeHighWater(_ context.Context, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.After(m.state.TimeHighWater) {
		m.state.TimeHighWater = t
	}
	return nil
}

// insertRaw writes a row straight into the store (a database writer that
// bypasses the service).
func (m *memRepo) insertRaw(rec Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, rec)
	m.state.Version++
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSvc(repo *memRepo, c *clock) *Service {
	s := NewService(repo, lkt.Verifier(), nil)
	s.SetClock(c.now)
	return s
}

// claims returns valid claims for license id, valid from nb for term.
func claims(id string, nb time.Time, term time.Duration, keys ...limits.GrantKey) licensekey.Claims {
	c := lkt.Claims(t0)
	c.ID, c.NotBefore, c.IssuedAt, c.ExpiresAt = id, nb, nb, nb.Add(term)
	if nb.After(t0) {
		c.IssuedAt = t0.Add(-48 * time.Hour) // a renewal issued before it starts
	}
	if len(keys) > 0 {
		c.Entitlements = keys
	}
	return c
}

// keySet is version 1 by the test root listing issuing key 0, long enough
// for every license of these tests.
func keySet() lkt.KeySet {
	ks := lkt.DefaultKeySet(t0)
	ks.IssuedAt, ks.NotAfter = t0.Add(-370*day), t0.Add(720*day)
	return ks
}

func file(c licensekey.Claims) []byte { return fileWithKeySet(c, keySet(), 0) }

// fileWithKeySet signs c with issuing key n under key set ks.
func fileWithKeySet(c licensekey.Claims, ks lkt.KeySet, n int) []byte {
	return lkt.Assemble(lkt.Envelope(lkt.IssuingKey(n), licensekey.PayloadType, lkt.ClaimsPayload(c)), ks.Sign())
}

func TestCommunityByDefault(t *testing.T) {
	ctx := context.Background()
	svc := newSvc(newMemRepo(), &clock{t0})
	st, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateCommunity || st.Current != nil || st.InstallationID != installID {
		t.Fatalf("status %+v", st)
	}
	for _, k := range limits.GrantKeys() {
		if st.Grants[k].Status != limits.GrantNone || svc.Has(ctx, k) {
			t.Errorf("%s granted without a license", k)
		}
	}
}

func TestActivate(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	actor := shared.NewID()
	sum, err := svc.Activate(ctx, file(claims("lic_A0000001", t0.Add(-day), 365*day)), SourceUpload, &actor)
	if err != nil {
		t.Fatal(err)
	}
	if sum.State != licensekey.StateActive || sum.LicenseID != "lic_A0000001" {
		t.Fatalf("summary %+v", sum)
	}
	if len(repo.recs) != 1 || repo.recs[0].AddedBy == nil || *repo.recs[0].AddedBy != actor || repo.recs[0].Source != SourceUpload {
		t.Fatalf("stored %+v", repo.recs)
	}
	for _, k := range limits.GrantKeys() {
		if !svc.Has(ctx, k) {
			t.Errorf("%s not granted after activation", k)
		}
	}
	// Grants are the same for every organization.
	a, _ := svc.Grants(ctx, shared.NewID())
	b, _ := svc.Grants(ctx, shared.NewID())
	for k := range a {
		if a[k] != b[k] {
			t.Errorf("grant %s differs between organizations", k)
		}
	}

	if _, err := svc.Activate(ctx, file(claims("lic_A0000001", t0.Add(-day), 365*day)), SourceUpload, nil); !errors.Is(err, ErrAlreadyStored) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := svc.Activate(ctx, file(claims("lic_B0000001", t0, day)), "email", nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown source: %v", err)
	}
}

func TestActivateRefusals(t *testing.T) {
	ctx := context.Background()
	good := file(claims("lic_C0000001", t0.Add(-day), 365*day))
	tampered := append([]byte{}, good...)
	tampered[len(tampered)/2] ^= 0x01
	bound := claims("lic_C0000002", t0.Add(-day), 365*day)
	bound.Bind = &licensekey.Binding{InstallationIDs: []string{"11111111-2222-4333-8444-555555555555"}}
	untrusted := keySet()
	untrusted.Root = lkt.OtherRoot()
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"tampered", tampered, licensekey.ErrMalformed},
		{"untrusted root", fileWithKeySet(claims("lic_C0000003", t0.Add(-day), 365*day), untrusted, 0), licensekey.ErrUntrustedRoot},
		{"bound to another installation", file(bound), licensekey.ErrBindingMismatch},
		{"already past grace", file(claims("lic_C0000004", t0.Add(-100*day), 30*day)), ErrExpired},
		{"oversized", make([]byte, 1<<20), licensekey.ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMemRepo()
			svc := newSvc(repo, &clock{t0})
			_, err := svc.Activate(ctx, tc.in, SourceUpload, nil)
			if !errors.Is(err, tc.want) && (tc.name != "tampered" || !errors.Is(err, licensekey.ErrBadSignature)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if len(repo.recs) != 0 || repo.state.Version != 1 {
				t.Fatal("a refused license was stored")
			}
		})
	}
}

// A renewal uploaded early waits and takes over at its not_before with no
// gap; licenses are not merged.
func TestRenewalWithoutGap(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	oldExp := t0.Add(10 * day)
	if _, err := svc.Activate(ctx, file(claims("lic_D0000001", t0.Add(-355*day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(ctx, file(claims("lic_D0000002", oldExp.Add(-day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.Status(ctx)
	if st.Current.LicenseID != "lic_D0000001" || st.State != string(licensekey.StateExpiring) || len(st.Pending) != 1 {
		t.Fatalf("before the renewal starts: %s %s pending=%d", st.Current.LicenseID, st.State, len(st.Pending))
	}
	for _, at := range []time.Time{oldExp.Add(-day), oldExp, oldExp.Add(20 * day)} {
		c.t = at
		svc.invalidate()
		st, _ = svc.Status(ctx)
		if st.Current.LicenseID != "lic_D0000002" || st.State != string(licensekey.StateActive) || !svc.Has(ctx, limits.GrantAIWorker) {
			t.Fatalf("at %s: %s %s", at, st.Current.LicenseID, st.State)
		}
	}
}

// A renewal without a key ends that key at the renewal's start: expired,
// settings read-only for the read-only period. Other keys continue.
func TestRenewalDroppingAKey(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	_, _ = svc.Activate(ctx, file(claims("lic_E0000001", t0.Add(-300*day), 365*day)), SourceUpload, nil)
	renewStart := t0.Add(-day)
	if _, err := svc.Activate(ctx, file(claims("lic_E0000002", renewStart, 365*day, limits.GrantAssetCollector)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.Status(ctx)
	if g := st.Grants[limits.GrantAssetCollector]; g.Status != limits.GrantActive {
		t.Fatalf("kept key: %+v", g)
	}
	g := st.Grants[limits.GrantAIWorker]
	if g.Status != limits.GrantExpired || !g.ReadOnlyUntil.Equal(renewStart.Add(limits.GrantReadOnlyPeriod)) {
		t.Fatalf("dropped key: %+v", g)
	}
}

func TestExpiryAndGrace(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	exp := t0.Add(5 * day)
	if _, err := svc.Activate(ctx, file(claims("lic_F0000001", t0.Add(-360*day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		at    time.Time
		state licensekey.State
		grant limits.GrantStatus
		has   bool
	}{
		{t0, licensekey.StateExpiring, limits.GrantExpiring, true},
		{exp, licensekey.StateGrace, limits.GrantGrace, true},
		{exp.Add(14*day - time.Second), licensekey.StateGrace, limits.GrantGrace, true},
		{exp.Add(14 * day), licensekey.StateExpired, limits.GrantExpired, false},
	}
	for _, s := range steps {
		c.t = s.at
		svc.refresh(ctx)
		st, _ := svc.Status(ctx)
		g := st.Grants[limits.GrantAIWorker]
		if st.State != string(s.state) || g.Status != s.grant || svc.Has(ctx, limits.GrantAIWorker) != s.has {
			t.Fatalf("at %s: state %s grant %s", s.at, st.State, g.Status)
		}
	}
	g, _ := svc.Status(ctx)
	if want := exp.Add(14 * day).Add(limits.GrantReadOnlyPeriod); !g.Grants[limits.GrantAIWorker].ReadOnlyUntil.Equal(want) {
		t.Fatalf("read-only until %s, want %s", g.Grants[limits.GrantAIWorker].ReadOnlyUntil, want)
	}
}

// Winding the clock back after expiry does not revive the license: the
// stored high-water mark holds the effective time.
func TestClockRollbackDoesNotRevive(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	_, _ = svc.Activate(ctx, file(claims("lic_G0000001", t0.Add(-360*day), 365*day)), SourceUpload, nil)
	c.t = t0.Add(30 * day) // past expiry + grace
	svc.refresh(ctx)       // persists the high-water mark
	if repo.state.TimeHighWater.Before(c.t) {
		t.Fatalf("high-water mark not stored: %s", repo.state.TimeHighWater)
	}
	c.t = t0 // clock wound back
	fresh := newSvc(repo, c)
	st, _ := fresh.Status(ctx)
	if st.State != string(licensekey.StateExpired) || fresh.Has(ctx, limits.GrantAIWorker) || !st.ClockBehind {
		t.Fatalf("after rollback: state %s clockBehind=%v", st.State, st.ClockBehind)
	}
	// The mark never goes down.
	_ = repo.AdvanceTimeHighWater(ctx, t0)
	if repo.state.TimeHighWater.Before(t0.Add(30 * day)) {
		t.Fatal("high-water mark lowered")
	}
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	sum, _ := svc.Activate(ctx, file(claims("lic_H0000001", t0.Add(-day), 365*day)), SourceUpload, nil)
	c.t = t0.Add(time.Hour)
	actor := shared.NewID()
	if err := svc.Remove(ctx, sum.RecordID, &actor); err != nil {
		t.Fatal(err)
	}
	if err := svc.Remove(ctx, sum.RecordID, &actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	st, _ := svc.Status(ctx)
	g := st.Grants[limits.GrantAIWorker]
	if st.State != StateCommunity || g.Status != limits.GrantExpired || !g.ReadOnlyUntil.Equal(c.t.Add(limits.GrantReadOnlyPeriod)) || svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatalf("after removal: %s %+v", st.State, g)
	}
	// The history keeps the row; the same license can be added again.
	if len(repo.recs) != 1 {
		t.Fatal("removal deleted the row")
	}
	if _, err := svc.Activate(ctx, file(claims("lic_H0000001", t0.Add(-day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatalf("re-add after removal: %v", err)
	}
}

// Rows written straight into the database grant nothing: every load
// re-verifies the stored file.
func TestForgedRowsGrantNothing(t *testing.T) {
	ctx := context.Background()
	repo := newMemRepo()
	untrusted := keySet()
	untrusted.Root = lkt.OtherRoot()
	forged := claims("lic_I0000001", t0.Add(-day), 365*day)
	repo.insertRaw(Record{ID: shared.NewID(), LicenseID: forged.ID, File: fileWithKeySet(forged, untrusted, 0),
		Entitlements: limits.GrantKeys(), NotBefore: forged.NotBefore, ExpiresAt: forged.ExpiresAt})
	repo.insertRaw(Record{ID: shared.NewID(), LicenseID: "lic_I0000002", File: []byte(`{"license":{},"keyset":{}}`)})
	// A valid file under a row claiming another license id.
	valid := claims("lic_I0000003", t0.Add(-day), 365*day)
	repo.insertRaw(Record{ID: shared.NewID(), LicenseID: "lic_I0000099", File: file(valid)})
	svc := newSvc(repo, &clock{t0})
	st, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateCommunity || st.Invalid != 3 || svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatalf("forged rows: state %s invalid %d", st.State, st.Invalid)
	}
}

// Key-set rollback is refused when a file is added; revocations of the
// newest key set apply to every stored license; a stored license keeps
// working after a renewal brings a newer key set.
func TestKeySetRollbackAndRevocation(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	svc := newSvc(repo, c)
	v1 := keySet()
	v2 := keySet()
	v2.Version, v2.Keys = 2, []ed25519.PublicKey{lkt.Public(lkt.IssuingKey(1))}

	if _, err := svc.Activate(ctx, fileWithKeySet(claims("lic_J0000001", t0.Add(-day), 365*day), v1, 0), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(ctx, fileWithKeySet(claims("lic_J0000002", t0.Add(300*day), 365*day), v2, 1), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	if repo.state.KeySetHighWater != 2 {
		t.Fatalf("key-set high-water %d", repo.state.KeySetHighWater)
	}
	if st, _ := svc.Status(ctx); st.Current.LicenseID != "lic_J0000001" || !svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("stored license stopped working after a newer key set arrived")
	}
	if _, err := svc.Activate(ctx, fileWithKeySet(claims("lic_J0000003", t0.Add(-day), 365*day), v1, 0), SourceUpload, nil); !errors.Is(err, licensekey.ErrKeySetRollback) {
		t.Fatalf("rolled-back key set: %v", err)
	}

	v3 := v2
	v3.Version = 3
	v3.Revoked.LicenseIDs = []string{"lic_J0000001"}
	if _, err := svc.Activate(ctx, fileWithKeySet(claims("lic_J0000004", t0.Add(350*day), 365*day), v3, 1), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.Status(ctx)
	if svc.Has(ctx, limits.GrantAIWorker) || st.Invalid != 1 {
		t.Fatalf("revoked license still in force: %s invalid %d", st.State, st.Invalid)
	}
}

// Another replica's write is picked up on the next refresh (version check).
func TestReloadOnOtherReplicaWrite(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	a, b := newSvc(repo, c), newSvc(repo, c)
	if b.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("granted before any license")
	}
	if _, err := a.Activate(ctx, file(claims("lic_K0000001", t0.Add(-day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	b.refresh(ctx)
	if !b.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("replica did not reload after the version changed")
	}
}

// Storage errors: before the first load every grant is off; afterwards the
// previous state is kept.
func TestFailClosedThenKeepPrevious(t *testing.T) {
	ctx := context.Background()
	repo, c := newMemRepo(), &clock{t0}
	repo.failAll = errors.New("db down")
	svc := newSvc(repo, c)
	if svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("granted while the state cannot be read")
	}
	if _, err := svc.Grants(ctx, shared.NewID()); err == nil {
		t.Fatal("Grants hid the read error")
	}
	repo.failAll = nil
	if _, err := svc.Activate(ctx, file(claims("lic_L0000001", t0.Add(-day), 365*day)), SourceUpload, nil); err != nil {
		t.Fatal(err)
	}
	if !svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("not granted")
	}
	repo.failAll = errors.New("db down again")
	c.t = t0.Add(10 * time.Minute) // snapshot stale: reload fails, previous kept
	svc.refresh(ctx)
	if !svc.Has(ctx, limits.GrantAIWorker) {
		t.Fatal("a storage error dropped the license in force")
	}
}

// What organizations can reach (grant states) carries nothing of the
// license: a new field on limits.Grant must be reviewed here first.
func TestGrantStateCarriesNoLicenseData(t *testing.T) {
	want := []string{"Key", "Status", "ExpiresAt", "GraceEndsAt", "ReadOnlyUntil"}
	typ := reflect.TypeOf(limits.Grant{})
	got := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("limits.Grant fields %v; organizations must never see license data (licensee, customer, file)", got)
	}
}
