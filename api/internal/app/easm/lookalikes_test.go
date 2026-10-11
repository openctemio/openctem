package easm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeLookalikeStore struct {
	owns    bool
	watches map[string]*lookalike.Watch
	cands   map[string]*lookalike.CandidateRecord
}

func newFakeLookalikeStore() *fakeLookalikeStore {
	return &fakeLookalikeStore{owns: true, watches: map[string]*lookalike.Watch{}, cands: map[string]*lookalike.CandidateRecord{}}
}

func (f *fakeLookalikeStore) OwnsRoot(context.Context, shared.ID, string) (bool, error) {
	return f.owns, nil
}
func (f *fakeLookalikeStore) ListWatches(context.Context, shared.ID) ([]lookalike.Watch, error) {
	out := []lookalike.Watch{}
	for _, w := range f.watches {
		out = append(out, *w)
	}
	return out, nil
}
func (f *fakeLookalikeStore) GetWatch(_ context.Context, _ shared.ID, id string) (*lookalike.Watch, error) {
	if w, ok := f.watches[id]; ok {
		c := *w
		return &c, nil
	}
	return nil, shared.ErrNotFound
}
func (f *fakeLookalikeStore) CreateWatch(_ context.Context, _ shared.ID, domain string, techs []lookalike.Technique, maxN int, _ *shared.ID) (*lookalike.Watch, error) {
	w := &lookalike.Watch{ID: shared.NewID().String(), Domain: domain, Enabled: true, Techniques: techs, MaxCandidates: maxN}
	f.watches[w.ID] = w
	return w, nil
}
func (f *fakeLookalikeStore) UpdateWatch(_ context.Context, _ shared.ID, id string, enabled bool, techs []lookalike.Technique, maxN int) (*lookalike.Watch, error) {
	w := f.watches[id]
	w.Enabled, w.Techniques, w.MaxCandidates, w.GeneratedAt = enabled, techs, maxN, nil
	return w, nil
}
func (f *fakeLookalikeStore) DeleteWatch(_ context.Context, _ shared.ID, id string) error {
	delete(f.watches, id)
	return nil
}
func (f *fakeLookalikeStore) ReplaceCandidates(_ context.Context, _ shared.ID, watchID string, cands []lookalike.Candidate, now time.Time) error {
	f.cands = map[string]*lookalike.CandidateRecord{}
	for _, c := range cands {
		f.cands[c.Domain] = &lookalike.CandidateRecord{WatchID: watchID, Domain: c.Domain, Technique: string(c.Technique), State: "unchecked"}
	}
	f.watches[watchID].GeneratedAt = &now
	return nil
}
func (f *fakeLookalikeStore) DueCandidates(_ context.Context, _ shared.ID, _ string, _, _ time.Time, limit int) ([]lookalike.CandidateRecord, error) {
	out := []lookalike.CandidateRecord{}
	for _, c := range f.cands {
		if len(out) < limit {
			out = append(out, *c)
		}
	}
	return out, nil
}
func (f *fakeLookalikeStore) SaveObservation(_ context.Context, _ shared.ID, _, domain string, o lookalike.Observation, _ bool, now time.Time) error {
	c := f.cands[domain]
	c.State = "unregistered"
	if o.Registered {
		c.State = "registered"
	}
	c.HasA, c.HasMX, c.CTCerts, c.LastCheckedAt = o.HasA, o.HasMX, o.CTCerts, &now
	return nil
}
func (f *fakeLookalikeStore) Registered(context.Context, shared.ID, string, int) ([]lookalike.CandidateRecord, error) {
	out := []lookalike.CandidateRecord{}
	for _, c := range f.cands {
		if c.State == "registered" {
			out = append(out, *c)
		}
	}
	return out, nil
}
func (f *fakeLookalikeStore) RootAsset(context.Context, shared.ID, string) (*shared.ID, error) {
	return nil, nil
}
func (f *fakeLookalikeStore) TenantsWithWatches(context.Context) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}

// fakeZone answers NS/A/MX for registered names, NXDOMAIN otherwise.
type fakeZone struct {
	registered map[string]bool
	mx         map[string]bool
	fail       map[string]bool
	asked      []string
}

func (z *fakeZone) Query(_ context.Context, name string, t dnsprobe.Type) (dnsprobe.Answer, error) {
	z.asked = append(z.asked, name)
	if z.fail[name] {
		return dnsprobe.Answer{}, dnsprobe.ErrTimeout
	}
	if !z.registered[name] {
		return dnsprobe.Answer{RCode: dnsprobe.RCodeNXDomain}, nil
	}
	a := dnsprobe.Answer{RCode: dnsprobe.RCodeSuccess}
	switch t {
	case dnsprobe.TypeNS:
		a.Records = []dnsprobe.Record{{Name: name, Type: dnsprobe.TypeNS, Value: "ns1.parking.example"}}
	case dnsprobe.TypeA:
		a.Records = []dnsprobe.Record{{Name: name, Type: dnsprobe.TypeA, Value: "203.0.113.5"}}
	case dnsprobe.TypeMX:
		if z.mx[name] {
			a.Records = []dnsprobe.Record{{Name: name, Type: dnsprobe.TypeMX, Value: "mx." + name}}
		}
	}
	return a, nil
}

type fakeCertCount struct{ n int }

func (c fakeCertCount) CountCerts(context.Context, string) (int, error) { return c.n, nil }

type fakeLookalikeExposures struct{ events []*exposuredom.ExposureEvent }

func (f *fakeLookalikeExposures) BulkUpsert(_ context.Context, ev []*exposuredom.ExposureEvent) error {
	f.events = append(f.events, ev...)
	return nil
}

type fakeLookalikeResolver struct{ fps []string }

func (f *fakeLookalikeResolver) ResolveAuto(_ context.Context, _ shared.ID, source string, fps []string, _ string) (int, error) {
	if source != LookalikeSource {
		return 0, errors.New("wrong source")
	}
	f.fps = append(f.fps, fps...)
	return len(fps), nil
}

func TestLookalikeService(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()

	t.Run("a watch needs one of the organization's root domains", func(t *testing.T) {
		store := newFakeLookalikeStore()
		svc := NewLookalikeService(store, nil, nil, nil, nil, nil)
		store.owns = false
		if _, err := svc.CreateWatch(ctx, tid, nil, "example.com", nil, 0); !errors.Is(err, ErrNotOwnRoot) {
			t.Fatalf("someone else's domain: %v", err)
		}
		store.owns = true
		for _, bad := range []string{"www.example.com", "co.uk"} {
			if _, err := svc.CreateWatch(ctx, tid, nil, bad, nil, 0); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s accepted: %v", bad, err)
			}
		}
		if _, err := svc.CreateWatch(ctx, tid, nil, "example.com", []string{"nope"}, 0); !errors.Is(err, shared.ErrValidation) {
			t.Fatal("unknown technique accepted")
		}
		if _, err := svc.CreateWatch(ctx, tid, nil, "example.com", nil, 5000); !errors.Is(err, shared.ErrValidation) {
			t.Fatal("oversized cap accepted")
		}
		w, err := svc.CreateWatch(ctx, tid, nil, "Example.com", []string{"tld"}, 50)
		if err != nil || w.Domain != "example.com" || w.GeneratedAt == nil || len(store.cands) == 0 {
			t.Fatalf("create: %v %+v %d", err, w, len(store.cands))
		}
	})

	t.Run("registered lookalikes become exposures, gone ones are resolved", func(t *testing.T) {
		store := newFakeLookalikeStore()
		zone := &fakeZone{registered: map[string]bool{"example.net": true, "example.org": true}, mx: map[string]bool{"example.net": true},
			fail: map[string]bool{"example.io": true}}
		ex, res := &fakeLookalikeExposures{}, &fakeLookalikeResolver{}
		svc := NewLookalikeService(store, zone, fakeCertCount{n: 2}, ex, res, nil)
		w, err := svc.CreateWatch(ctx, tid, nil, "example.com", []string{"tld"}, 30)
		if err != nil {
			t.Fatal(err)
		}
		n, err := svc.RunTenant(ctx, tid)
		if err != nil || n == 0 {
			t.Fatalf("run: %v %d", err, n)
		}
		if len(ex.events) != 2 {
			t.Fatalf("exposures: %d", len(ex.events))
		}
		sev := map[string]string{}
		for _, e := range ex.events {
			if e.EventType() != exposuredom.EventTypeLookalikeDomain || e.Source() != LookalikeSource {
				t.Fatalf("event: %s %s", e.EventType(), e.Source())
			}
			sev[e.Details()["domain"].(string)] = string(e.Severity())
		}
		if sev["example.net"] != "medium" || sev["example.org"] != "medium" { // MX; A with certificates
			t.Fatalf("severity: %v", sev)
		}
		if store.cands["example.io"].State != "unchecked" {
			t.Fatal("a resolver failure concluded something")
		}
		// No candidate host is ever asked: only the resolver.
		for _, name := range zone.asked {
			if name == "example.com" {
				t.Fatal("the watched root was queried as a candidate")
			}
		}
		// example.org lapses.
		delete(zone.registered, "example.org")
		if _, err := svc.RunTenant(ctx, tid); err != nil {
			t.Fatal(err)
		}
		if len(res.fps) != 1 || res.fps[0] != lookalikeFingerprint(tid, "example.org") {
			t.Fatalf("resolved: %v", res.fps)
		}
		// Deleting the watch resolves the rest.
		if err := svc.DeleteWatch(ctx, tid, w.ID); err != nil {
			t.Fatal(err)
		}
		if len(res.fps) != 2 {
			t.Fatalf("after delete: %v", res.fps)
		}
	})

	t.Run("a disabled watch is not checked", func(t *testing.T) {
		store := newFakeLookalikeStore()
		zone := &fakeZone{}
		svc := NewLookalikeService(store, zone, nil, nil, nil, nil)
		w, _ := svc.CreateWatch(ctx, tid, nil, "example.com", []string{"tld"}, 20)
		if _, err := svc.UpdateWatch(ctx, tid, w.ID, false, []string{"tld"}, 20); err != nil {
			t.Fatal(err)
		}
		if n, _ := svc.RunTenant(ctx, tid); n != 0 || len(zone.asked) != 0 {
			t.Fatalf("disabled watch checked: %d", n)
		}
	})
}

func TestObservationSeverity(t *testing.T) {
	cases := []struct {
		o    lookalike.Observation
		want string
	}{
		{lookalike.Observation{Registered: true}, "low"},
		{lookalike.Observation{Registered: true, HasA: true}, "low"},
		{lookalike.Observation{Registered: true, HasA: true, CTCerts: 1}, "medium"},
		{lookalike.Observation{Registered: true, HasMX: true}, "medium"},
	}
	for _, c := range cases {
		if got := c.o.Severity(); got != c.want {
			t.Errorf("%+v: %s, want %s", c.o, got, c.want)
		}
	}
}

func TestCrtShCounter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "example.net" || r.URL.Query().Get("exclude") != "expired" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[{"id":1},{"id":2},{"id":3}]`))
	}))
	defer srv.Close()
	c := &CrtSh{client: srv.Client(), base: srv.URL + "/"}
	if n, err := c.CountCerts(context.Background(), "example.net"); err != nil || n != 3 {
		t.Fatalf("count: %d %v", n, err)
	}
	guarded := NewCrtSh()
	guarded.base, guarded.wait = srv.URL+"/", 0
	if _, err := guarded.CountCerts(context.Background(), "example.net"); err == nil {
		t.Fatal("the guarded client reached a loopback server")
	}
}
