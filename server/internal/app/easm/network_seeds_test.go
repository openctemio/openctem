package easm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeSeedStore struct {
	seeds   map[string]*easmseed.Seed
	claimed map[string]time.Time
	saveErr string
}

func newFakeSeedStore() *fakeSeedStore {
	return &fakeSeedStore{seeds: map[string]*easmseed.Seed{}, claimed: map[string]time.Time{}}
}

func (f *fakeSeedStore) List(context.Context, shared.ID) ([]easmseed.Seed, error) {
	out := []easmseed.Seed{}
	for _, s := range f.seeds {
		out = append(out, *s)
	}
	return out, nil
}
func (f *fakeSeedStore) Get(_ context.Context, _ shared.ID, id string) (*easmseed.Seed, error) {
	if s, ok := f.seeds[id]; ok {
		c := *s
		return &c, nil
	}
	return nil, shared.ErrNotFound
}
func (f *fakeSeedStore) Create(_ context.Context, _ shared.ID, kind easmseed.Kind, value, label string, _ *shared.ID) (*easmseed.Seed, error) {
	for _, s := range f.seeds {
		if s.Kind == kind && strings.EqualFold(s.Value, value) {
			return nil, shared.ErrConflict
		}
	}
	s := &easmseed.Seed{ID: shared.NewID().String(), Kind: kind, Value: value, Label: label}
	f.seeds[s.ID] = s
	return s, nil
}
func (f *fakeSeedStore) Delete(_ context.Context, _ shared.ID, id string) error {
	delete(f.seeds, id)
	return nil
}
func (f *fakeSeedStore) ClaimExpansion(_ context.Context, _ shared.ID, id string, now time.Time, cooldown time.Duration) (bool, error) {
	if last, ok := f.claimed[id]; ok && now.Sub(last) < cooldown {
		return false, nil
	}
	f.claimed[id] = now
	return true, nil
}
func (f *fakeSeedStore) SaveExpansion(_ context.Context, _ shared.ID, id, holder string, prefixes []string, sugg []easmseed.ASNSuggestion, expandErr string) error {
	s := f.seeds[id]
	if expandErr != "" {
		f.saveErr = expandErr
		s.ExpandError = expandErr
		return nil
	}
	s.Holder, s.Prefixes, s.Suggestions = holder, prefixes, sugg
	return nil
}
func (f *fakeSeedStore) DueForExpansion(context.Context, time.Time, int) ([]easmseed.Ref, error) {
	out := []easmseed.Ref{}
	for id := range f.seeds {
		out = append(out, easmseed.Ref{TenantID: shared.NewID(), ID: id})
	}
	return out, nil
}
func (f *fakeSeedStore) Networks(context.Context, shared.ID) (easmseed.Networks, error) {
	return easmseed.Networks{}, nil
}

type fakeSource struct {
	holder   string
	prefixes []string
	sugg     []easmseed.ASNSuggestion
	err      error
}

func (f fakeSource) ASNHolder(context.Context, string) (string, error) { return f.holder, f.err }
func (f fakeSource) AnnouncedPrefixes(context.Context, string) ([]string, error) {
	return f.prefixes, f.err
}
func (f fakeSource) SearchASNs(context.Context, string) ([]easmseed.ASNSuggestion, error) {
	return f.sugg, f.err
}

func TestNetworkSeedService(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	newSvc := func(store *fakeSeedStore, src fakeSource) *NetworkSeedService {
		s := NewNetworkSeedService(store, src, scopedom.DefaultGuardrails(), nil)
		s.async = func(f func()) { f() }
		return s
	}

	t.Run("an ASN seed offers its prefixes through the guardrails", func(t *testing.T) {
		store := newFakeSeedStore()
		svc := newSvc(store, fakeSource{holder: "EXAMPLE-AS Example Corp", prefixes: []string{"198.51.100.0/24", "10.0.0.0/8", "203.0.0.0/8"}})
		v, err := svc.Create(ctx, tid, nil, easmseed.KindASN, "as64496", "")
		if err == nil || !errors.Is(err, shared.ErrValidation) || v != nil {
			t.Fatalf("documentation ASN accepted: %v", err)
		}
		if _, err = svc.Create(ctx, tid, nil, easmseed.KindASN, "as3333", "main"); err != nil {
			t.Fatal(err)
		}
		views, _ := svc.List(ctx, tid)
		if len(views) != 1 || views[0].Value != "AS3333" || views[0].Holder == "" {
			t.Fatalf("views: %+v", views)
		}
		got := map[string]PrefixSuggestion{}
		for _, p := range views[0].PrefixSuggestions {
			got[p.Prefix] = p
		}
		if !got["198.51.100.0/24"].Allowed || got["203.0.0.0/8"].Allowed || got["203.0.0.0/8"].Refusal == "" {
			t.Fatalf("guardrails not applied: %+v", got)
		}
		if _, err := svc.Create(ctx, tid, nil, easmseed.KindASN, "AS3333", ""); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("duplicate: %v", err)
		}
	})

	t.Run("a cloud provider's AS offers no prefixes", func(t *testing.T) {
		store := newFakeSeedStore()
		svc := newSvc(store, fakeSource{holder: "AMAZON-02 - Amazon.com, Inc.", prefixes: []string{"52.0.0.0/16"}})
		_, _ = svc.Create(ctx, tid, nil, easmseed.KindASN, "AS16509", "")
		views, _ := svc.List(ctx, tid)
		if !views[0].Shared || len(views[0].PrefixSuggestions) != 0 {
			t.Fatalf("shared AS offered prefixes: %+v", views[0])
		}
	})

	t.Run("an organization seed keeps only matching, unshared ASNs", func(t *testing.T) {
		store := newFakeSeedStore()
		svc := newSvc(store, fakeSource{sugg: []easmseed.ASNSuggestion{
			{ASN: "AS1", Description: "EXAMPLECORP-NET Examplecorp Ltd"},
			{ASN: "AS2", Description: "OTHER-NET Unrelated Inc"},
			{ASN: "AS3", Description: "Examplecorp on Cloudflare, Inc."},
		}})
		_, _ = svc.Create(ctx, tid, nil, easmseed.KindOrgName, "Examplecorp Ltd", "")
		views, _ := svc.List(ctx, tid)
		if len(views[0].Suggestions) != 1 || views[0].Suggestions[0].ASN != "AS1" {
			t.Fatalf("suggestions: %+v", views[0].Suggestions)
		}
	})

	t.Run("a source failure is recorded, the cooldown limits refreshes", func(t *testing.T) {
		store := newFakeSeedStore()
		svc := newSvc(store, fakeSource{err: errors.New("dial tcp: refused")})
		v, _ := svc.Create(ctx, tid, nil, easmseed.KindASN, "AS3333", "")
		if store.saveErr == "" || strings.Contains(store.saveErr, "refused") {
			t.Fatalf("error not recorded generically: %q", store.saveErr)
		}
		if err := svc.Expand(ctx, tid, v.ID); !errors.Is(err, ErrExpandTooSoon) {
			t.Fatalf("expand inside the cooldown: %v", err)
		}
		if err := svc.Expand(ctx, tid, shared.NewID().String()); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("expand of an unknown seed: %v", err)
		}
	})
}

func TestSeededNetwork(t *testing.T) {
	n := easmseed.Networks{ASNs: map[string]bool{"AS3333": true}, OrgNames: []string{"Examplecorp"}, Prefixes: []string{"198.51.100.0/24"}}
	cases := []struct {
		addr, asn, org string
		want           bool
	}{
		{"203.0.113.1", "AS3333", "", true},
		{"198.51.100.7", "", "", true},
		{"203.0.113.1", "AS1", "EXAMPLECORP-NET Examplecorp Ltd", true},
		{"203.0.113.1", "AS1", "Other", false},
	}
	for _, c := range cases {
		if got := seededNetwork(n, c.addr, c.asn, c.org); got != c.want {
			t.Errorf("seededNetwork(%s, %s, %q) = %v", c.addr, c.asn, c.org, got)
		}
	}
}

func TestRIPEstatClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sourceapp") != "openctem" {
			http.Error(w, "no sourceapp", http.StatusBadRequest)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "announced-prefixes"):
			_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"193.0.10.1/23"},{"prefix":"193.0.10.0/23"},{"prefix":"bogus"},{"prefix":"2001:67c:2e8::/48"}]}}`))
		case strings.Contains(r.URL.Path, "as-overview"):
			_, _ = w.Write([]byte(`{"data":{"holder":"RIPE-NCC-AS Reseaux IP Europeens\u0000\n"}}`))
		case strings.Contains(r.URL.Path, "searchcomplete"):
			_, _ = w.Write([]byte(`{"data":{"categories":[{"category":"Prefixes","suggestions":[{"value":"1.2.3.0/24"}]},{"category":"ASNs","suggestions":[{"value":"AS3333","description":"RIPE"},{"value":"AS64512","description":"private"},{"value":"junk"}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newRIPEstatForTest(srv.Client(), srv.URL+"/data/")
	ctx := context.Background()
	p, err := c.AnnouncedPrefixes(ctx, "AS3333")
	if err != nil || len(p) != 2 || p[0] != "193.0.10.0/23" {
		t.Fatalf("prefixes: %v %v", p, err)
	}
	h, err := c.ASNHolder(ctx, "AS3333")
	if err != nil || strings.ContainsAny(h, "\x00\n") || !strings.HasPrefix(h, "RIPE-NCC-AS") {
		t.Fatalf("holder: %q %v", h, err)
	}
	s, err := c.SearchASNs(ctx, "ripe")
	if err != nil || len(s) != 1 || s[0].ASN != "AS3333" {
		t.Fatalf("search: %+v %v", s, err)
	}
	if _, err := c.ASNHolder(ctx, "x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The production client refuses internal targets (SSRF guard).
func TestRIPEstatClientIsGuarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"holder":"x"}}`))
	}))
	defer srv.Close()
	c := NewRIPEstat()
	c.base, c.wait = srv.URL+"/data/", 0
	if _, err := c.ASNHolder(context.Background(), "AS3333"); err == nil {
		t.Fatal("the guarded client reached a loopback server")
	}
}

type seedSettings struct {
	off bool
	err error
}

func (s seedSettings) GetEASMSettings(context.Context, string) (*tenant.EASMSettings, error) {
	return &tenant.EASMSettings{NetworkLookupsDisabled: s.off}, s.err
}

type countingSource struct {
	fakeSource
	calls *int
}

func (c countingSource) ASNHolder(ctx context.Context, asn string) (string, error) {
	*c.calls++
	return c.fakeSource.ASNHolder(ctx, asn)
}

// The organization's opt-out (and an unreadable setting) sends nothing to
// RIPEstat; a manual refresh is refused.
func TestNetworkSeedLookupsOptOut(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	for _, st := range []seedSettings{{off: true}, {err: errors.New("db down")}} {
		calls := 0
		store := newFakeSeedStore()
		svc := NewNetworkSeedService(store, countingSource{fakeSource{holder: "X"}, &calls}, scopedom.DefaultGuardrails(), nil)
		svc.async = func(f func()) { f() }
		svc.SetSettings(st)
		v, err := svc.Create(ctx, tid, nil, easmseed.KindASN, "AS3333", "")
		if err != nil {
			t.Fatal(err)
		}
		if calls != 0 || store.seeds[v.ID].ExpandError == "" {
			t.Fatalf("%+v: source called %d times, error %q", st, calls, store.seeds[v.ID].ExpandError)
		}
		store.claimed = map[string]time.Time{}
		if err := svc.Expand(ctx, tid, v.ID); !errors.Is(err, ErrLookupsOff) {
			t.Fatalf("%+v: manual refresh: %v", st, err)
		}
	}
}
