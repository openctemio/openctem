package versioncheck

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// memRepo is Repository in memory, with the same conditional semantics as
// the Postgres one.
type memRepo struct {
	mu     sync.Mutex
	exists bool
	st     State
}

func (m *memRepo) Get(context.Context) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st, nil
}

func (m *memRepo) ClaimDue(_ context.Context, now, first, next time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exists {
		m.exists, m.st.NextCheckAt = true, &first
	}
	if m.st.NextCheckAt.After(now) {
		return false, nil
	}
	m.st.NextCheckAt, m.st.LastAttemptAt = &next, &now
	return true, nil
}

func (m *memRepo) Apply(_ context.Context, v *releasefeed.Verified, origin string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.AppliedSequence > v.Feed.Sequence ||
		(m.st.AppliedSequence == v.Feed.Sequence && m.st.FeedDigest != v.Digest) {
		return false, nil
	}
	f := v.Feed
	if !m.exists { // the column default
		m.exists, m.st.NextCheckAt = true, &now
	}
	m.st.Feed, m.st.Origin, m.st.AppliedSequence = &f, origin, f.Sequence
	m.st.FeedDigest = v.Digest
	m.st.AppliedAt, m.st.LastError, m.st.ConsecutiveFailures = &now, "", 0
	return true, nil
}

func (m *memRepo) RecordFailure(_ context.Context, code string, now time.Time, next func(int) time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.ConsecutiveFailures++
	m.st.LastError, m.st.LastAttemptAt = code, &now
	n := next(m.st.ConsecutiveFailures)
	m.st.NextCheckAt = &n
	return m.st.ConsecutiveFailures, nil
}

type keys struct {
	online ed25519.PrivateKey
}

func newKeys(t *testing.T) keys {
	t.Helper()
	return keys{online: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))}
}

// pinned is the hex public key a build pins for this key.
func (k keys) pinned() string { return hex.EncodeToString(k.online.Public().(ed25519.PublicKey)) }

func (k keys) feed(t *testing.T, seq uint64, issued time.Time, latest string) []byte {
	t.Helper()
	raw, err := releasefeed.Build(k.online, releasefeed.Feed{
		Sequence: seq, IssuedAt: issued, ExpiresAt: issued.Add(30 * 24 * time.Hour),
		Releases: []releasefeed.Release{{Version: latest, PublishedAt: issued}},
		Advisories: []releasefeed.Advisory{{ID: "OCTEM-2026-0001", Severity: "critical", Title: "t",
			FixedIn: latest, PublishedAt: issued}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type server struct {
	srv     *httptest.Server
	mu      sync.Mutex
	body    []byte
	status  int
	headers []http.Header
	queries []string
}

func newServer(t *testing.T) *server {
	s := &server{status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.headers = append(s.headers, r.Header.Clone())
		s.queries = append(s.queries, r.URL.RawQuery)
		w.WriteHeader(s.status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newService(repo Repository, roots []string, url string, c *clock, running string) *Service {
	return New(repo, Config{Enabled: true, URL: url, Keys: roots, Running: running, Client: http.DefaultClient,
		Now: c.Now, Jitter: func(time.Duration) time.Duration { return 0 }}, logger.NewNop())
}

func TestRunDue_FetchVerifyApply(t *testing.T) {
	k, srv, repo, c := newKeys(t), newServer(t), &memRepo{}, &clock{now: t0}
	srv.body = k.feed(t, 100, t0.Add(-time.Hour), "v0.9.8")
	svc := newService(repo, []string{k.pinned()}, srv.srv.URL+"/openctem-releases.json", c, "v0.9.7")
	ctx := context.Background()

	// First call creates the schedule only: the first check waits a while
	// after start-up.
	if err := svc.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(srv.headers) != 0 {
		t.Fatal("fetched at start-up")
	}
	c.now = c.now.Add(FirstCheckMin)
	if err := svc.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	if len(srv.headers) != 1 {
		t.Fatalf("fetches = %d", len(srv.headers))
	}
	// The request names nothing about the instance.
	h := srv.headers[0]
	if h.Get("User-Agent") != UserAgent || h.Get("Cookie") != "" || h.Get("Referer") != "" || h.Get("Authorization") != "" || srv.queries[0] != "" {
		t.Fatalf("identifying request: %v %q", h, srv.queries[0])
	}
	v, err := svc.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Source != OriginOnline || !v.UpdateAvailable || v.Severity != "critical" || v.FixedIn != "v0.9.8" || v.LastError != "" {
		t.Fatalf("view = %+v", v)
	}
	// Not due again for a day.
	c.now = c.now.Add(time.Hour)
	_ = svc.RunDue(ctx)
	if len(srv.headers) != 1 {
		t.Fatal("fetched again before the next check")
	}
}

func TestRunDue_DisabledOrUnconfiguredSendsNothing(t *testing.T) {
	k, srv, c := newKeys(t), newServer(t), &clock{now: t0}
	srv.body = k.feed(t, 1, t0, "v0.9.8")
	off := New(&memRepo{}, Config{Enabled: false, URL: srv.srv.URL, Keys: []string{k.pinned()}, Client: http.DefaultClient, Now: c.Now}, logger.NewNop())
	noKey := newService(&memRepo{}, nil, srv.srv.URL, c, "v0.9.7")
	for i := 0; i < 3; i++ {
		c.now = c.now.Add(48 * time.Hour)
		_ = off.RunDue(context.Background())
		_ = noKey.RunDue(context.Background())
	}
	if len(srv.headers) != 0 {
		t.Fatalf("sent %d requests while disabled or without a key", len(srv.headers))
	}
	v, _ := noKey.View(context.Background())
	if v.Configured || v.NextCheckAt != nil {
		t.Fatalf("view = %+v", v)
	}
}

// Offline: failures are recorded with a code, never returned, and after
// three the check backs off to weekly.
func TestRunDue_OfflineBacksOff(t *testing.T) {
	k, repo, c := newKeys(t), &memRepo{}, &clock{now: t0}
	svc := newService(repo, []string{k.pinned()}, "http://127.0.0.1:1/unreachable", c, "v0.9.7")
	ctx := context.Background()
	_ = svc.RunDue(ctx)
	for i := 1; i <= 4; i++ {
		c.now = *repo.st.NextCheckAt
		if err := svc.RunDue(ctx); err != nil {
			t.Fatalf("an offline check returned %v", err)
		}
		gap := repo.st.NextCheckAt.Sub(c.now)
		want := CheckInterval
		if i >= OfflineAfter {
			want = OfflineInterval
		}
		if gap != want || repo.st.LastError != ErrCodeUnreachable || repo.st.ConsecutiveFailures != i {
			t.Fatalf("failure %d: gap %s, state %+v", i, gap, repo.st)
		}
	}
}

func TestRunDue_RefusedAnswers(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	other.online = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	cases := map[string]struct {
		status int
		body   func(t *testing.T) []byte
		code   string
	}{
		"http error":   {http.StatusNotFound, func(*testing.T) []byte { return nil }, ErrCodeHTTPStatus},
		"oversize":     {http.StatusOK, func(*testing.T) []byte { return bytes.Repeat([]byte("a"), releasefeed.MaxBundleBytes+1) }, ErrCodeTooLarge},
		"garbage":      {http.StatusOK, func(*testing.T) []byte { return []byte("<html>") }, ErrCodeInvalid},
		"unpinned key": {http.StatusOK, func(t *testing.T) []byte { return other.feed(t, 5, t0, "v0.9.8") }, ErrCodeInvalid},
		"expired":      {http.StatusOK, func(t *testing.T) []byte { return k.feed(t, 5, t0.Add(-31*24*time.Hour), "v0.9.8") }, ErrCodeExpired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, repo, c := newServer(t), &memRepo{}, &clock{now: t0}
			srv.status, srv.body = tc.status, tc.body(t)
			svc := newService(repo, []string{k.pinned()}, srv.srv.URL, c, "v0.9.7")
			_ = svc.RunDue(context.Background())
			c.now = *repo.st.NextCheckAt
			if err := svc.RunDue(context.Background()); err != nil {
				t.Fatal(err)
			}
			if repo.st.LastError != tc.code || repo.st.Feed != nil {
				t.Fatalf("state = %+v", repo.st)
			}
		})
	}
}

// An older feed never replaces a newer one, online or imported.
func TestRollbackRefused(t *testing.T) {
	k, srv, repo, c := newKeys(t), newServer(t), &memRepo{}, &clock{now: t0}
	svc := newService(repo, []string{k.pinned()}, srv.srv.URL, c, "v0.9.7")
	ctx := context.Background()
	if _, err := svc.Import(ctx, k.feed(t, 200, t0.Add(-time.Hour), "v0.9.9")); err != nil {
		t.Fatal(err)
	}
	var ie *ImportError
	if _, err := svc.Import(ctx, k.feed(t, 150, t0.Add(-2*time.Hour), "v0.9.8")); !errors.As(err, &ie) || ie.Code != ErrCodeRollback {
		t.Fatalf("older import: %v", err)
	}
	srv.body = k.feed(t, 150, t0.Add(-2*time.Hour), "v0.9.8")
	_ = svc.RunDue(ctx)
	c.now = *repo.st.NextCheckAt
	_ = svc.RunDue(ctx)
	if repo.st.AppliedSequence != 200 || repo.st.LastError != ErrCodeRollback || repo.st.Origin != OriginImport {
		t.Fatalf("state = %+v", repo.st)
	}
	// The same feed again is accepted (a re-fetch of an unchanged file).
	if _, err := svc.Import(ctx, k.feed(t, 200, t0.Add(-time.Hour), "v0.9.9")); err != nil {
		t.Fatalf("same sequence: %v", err)
	}
}

// The same sequence is accepted again only with the same bytes: a second
// feed under an applied sequence is a replay or a signing fault.
func TestSameSequenceOtherBytesRefused(t *testing.T) {
	k, srv, repo, c := newKeys(t), newServer(t), &memRepo{}, &clock{now: t0}
	svc := newService(repo, []string{k.pinned()}, srv.srv.URL, c, "v0.9.7")
	ctx := context.Background()
	if _, err := svc.Import(ctx, k.feed(t, 300, t0.Add(-time.Hour), "v0.9.8")); err != nil {
		t.Fatal(err)
	}
	var ie *ImportError
	if _, err := svc.Import(ctx, k.feed(t, 300, t0.Add(-time.Hour), "v0.9.9")); !errors.As(err, &ie) || ie.Code != ErrCodeConflict {
		t.Fatalf("same sequence, other bytes: %v", err)
	}
	srv.body = k.feed(t, 300, t0.Add(-time.Hour), "v0.9.9")
	_ = svc.RunDue(ctx)
	if repo.st.LastError != ErrCodeConflict || repo.st.Feed.Releases[0].Version != "v0.9.8" {
		t.Fatalf("online: %+v", repo.st)
	}
	if _, err := svc.Import(ctx, k.feed(t, 300, t0.Add(-time.Hour), "v0.9.8")); err != nil {
		t.Fatalf("identical feed: %v", err)
	}
}

func TestImport(t *testing.T) {
	k, c := newKeys(t), &clock{now: t0}
	ctx := context.Background()
	var ie *ImportError
	if _, err := newService(&memRepo{}, nil, "", c, "v0.9.7").Import(ctx, k.feed(t, 1, t0, "v0.9.8")); !errors.As(err, &ie) || ie.Code != ErrCodeNoKey {
		t.Fatalf("no key: %v", err)
	}
	svc := newService(&memRepo{}, []string{k.pinned()}, "", c, "v0.9.8")
	if _, err := svc.Import(ctx, bytes.Repeat([]byte("a"), releasefeed.MaxBundleBytes+1)); !errors.As(err, &ie) || ie.Code != ErrCodeTooLarge {
		t.Fatalf("oversize: %v", err)
	}
	tampered := bytes.Replace(k.feed(t, 1, t0, "v0.9.8"), []byte(`"payload": "`), []byte(`"payload": "A`), 1)
	if _, err := svc.Import(ctx, tampered); !errors.As(err, &ie) || ie.Code != ErrCodeInvalid {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := svc.Import(ctx, k.feed(t, 1, t0, "v0.9.8")); err != nil {
		t.Fatal(err)
	}
	v, _ := svc.View(ctx)
	if v.Source != OriginImport || v.UpdateAvailable || len(v.Advisories) != 0 || v.Latest != "v0.9.8" || v.FeedExpiresAt == nil {
		t.Fatalf("view = %+v", v)
	}
	// Offline import works with the online check disabled.
	off := New(&memRepo{}, Config{Enabled: false, Keys: []string{k.pinned()}, Running: "v0.9.7", Now: c.Now}, logger.NewNop())
	if _, err := off.Import(ctx, k.feed(t, 1, t0, "v0.9.8")); err != nil {
		t.Fatal(err)
	}
	if v, _ := off.View(ctx); v.Enabled || !v.UpdateAvailable {
		t.Fatalf("disabled view = %+v", v)
	}
}

// The production client refuses a redirect from https to http and long
// redirect chains.
func TestClientRedirectPolicy(t *testing.T) {
	c := newClient()
	req := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		return r
	}
	if err := c.CheckRedirect(req("http://example.com/x"), []*http.Request{req("https://example.com/feed.json")}); err == nil {
		t.Fatal("followed a redirect to http")
	}
	via := []*http.Request{req("https://a"), req("https://b"), req("https://c")}
	if err := c.CheckRedirect(req("https://d"), via); err == nil {
		t.Fatal("followed more than 3 redirects")
	}
	if err := c.CheckRedirect(req("https://objects.example.com/x"), via[:1]); err != nil {
		t.Fatalf("refused a normal redirect: %v", err)
	}
}

// componentFeed is a feed that lists one sensor release.
func (k keys) componentFeed(t *testing.T, seq uint64, issued time.Time, sensorVersion string) []byte {
	t.Helper()
	raw, err := releasefeed.Build(k.online, releasefeed.Feed{
		Sequence: seq, IssuedAt: issued, ExpiresAt: issued.Add(30 * 24 * time.Hour),
		Releases:   []releasefeed.Release{{Version: "v0.9.8", PublishedAt: issued}},
		Advisories: []releasefeed.Advisory{},
		Components: []releasefeed.Component{{Component: "sensor", Version: sensorVersion, PublishedAt: issued}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// OnFeed receives the feed after an online check stores it, after an import,
// and on Refresh (what every replica runs each tick); a refused feed is
// never handed on. The console view lists the components.
func TestOnFeed_OnlineImportRefresh(t *testing.T) {
	k, srv, repo, c := newKeys(t), newServer(t), &memRepo{}, &clock{now: t0}
	var got []string
	onFeed := func(f *releasefeed.Feed) {
		if f == nil {
			got = append(got, "nil")
			return
		}
		got = append(got, f.ComponentVersions()["sensor"].Version)
	}
	svc := New(repo, Config{Enabled: true, URL: srv.srv.URL, Keys: []string{k.pinned()}, Running: "v0.9.7",
		Client: http.DefaultClient, Now: c.Now, Jitter: func(time.Duration) time.Duration { return 0 }, OnFeed: onFeed}, logger.NewNop())
	ctx := context.Background()

	// Nothing stored yet: Refresh hands on nil (the built-in versions apply).
	if err := svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	srv.body = k.componentFeed(t, 100, t0.Add(-time.Hour), "v0.30.0")
	_ = svc.RunDue(ctx) // schedules the first check
	c.now = c.now.Add(FirstCheckMin)
	if err := svc.RunDue(ctx); err != nil {
		t.Fatal(err)
	}
	// An imported newer feed.
	if _, err := svc.Import(ctx, k.componentFeed(t, 200, t0, "v0.31.0")); err != nil {
		t.Fatal(err)
	}
	// SECURITY: a replayed older feed is refused and not handed on.
	if _, err := svc.Import(ctx, k.componentFeed(t, 150, t0, "v0.1.0")); err == nil {
		t.Fatal("older feed accepted")
	}
	if err := svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"nil", "v0.30.0", "v0.31.0", "v0.31.0"}
	if len(got) != len(want) {
		t.Fatalf("OnFeed calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OnFeed calls = %v, want %v", got, want)
		}
	}
	v, err := svc.View(ctx)
	if err != nil || len(v.Components) != 1 || v.Components[0].Version != "v0.31.0" {
		t.Fatalf("view components = %+v (%v)", v.Components, err)
	}
	// Without a hook, Refresh is a no-op.
	if err := newService(repo, []string{k.pinned()}, "", c, "v0.9.7").Refresh(ctx); err != nil {
		t.Fatal(err)
	}
}
