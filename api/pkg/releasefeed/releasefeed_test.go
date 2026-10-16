package releasefeed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

var testNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

type fixture struct {
	root, online ed25519.PrivateKey
	keySet       []byte
	trust        Trust
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: seedKey(1), online: seedKey(2)}
	ks, err := SignKeySet(f.root, 3, testNow.Add(-time.Hour), testNow.Add(90*24*time.Hour), f.online.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	f.keySet = ks
	f.trust = Trust{Roots: []string{jobsign.KeyID(f.root.Public().(ed25519.PublicKey))}}
	return f
}

func sampleFeed(seq uint64) Feed {
	return Feed{
		Sequence: seq, IssuedAt: testNow.Add(-time.Hour), ExpiresAt: testNow.Add(30 * 24 * time.Hour),
		Releases: []Release{
			{Version: "v0.9.7", PublishedAt: testNow.Add(-72 * time.Hour), NotesURL: "https://github.com/openctemio/openctem/releases/tag/v0.9.7"},
			{Version: "v0.9.8", PublishedAt: testNow.Add(-24 * time.Hour), NotesURL: "https://github.com/openctemio/openctem/releases/tag/v0.9.8"},
		},
		Advisories: []Advisory{{
			ID: "OCTEM-2026-0001", Severity: "high", Title: "Session fixation in the console", Introduced: "v0.9.0",
			FixedIn: "v0.9.8", PublishedAt: testNow.Add(-24 * time.Hour), URL: "https://openctem.io/security/OCTEM-2026-0001",
		}},
	}
}

func (f *fixture) build(t *testing.T, feed Feed) []byte {
	t.Helper()
	raw, err := Build(f.keySet, f.online, feed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerify_Valid(t *testing.T) {
	f := newFixture(t)
	v, err := Verify(f.build(t, sampleFeed(100)), f.trust, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if v.KeySetVersion != 3 || v.Feed.Sequence != 100 || len(v.Feed.Releases) != 2 || len(v.Digest) != 64 {
		t.Fatalf("verified = %+v", v)
	}
}

func TestVerify_NoPinnedRoot(t *testing.T) {
	f := newFixture(t)
	if _, err := Verify(f.build(t, sampleFeed(1)), Trust{}, testNow); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("err = %v, want ErrNoRoot", err)
	}
	if len(PinnedRoots) != 0 {
		// A root is pinned in this build: it must be a well-formed key id.
		for _, r := range PinnedRoots {
			if !strings.HasPrefix(r, "SHA256:") || len(r) != len("SHA256:")+64 {
				t.Fatalf("pinned root %q is not a key id", r)
			}
		}
	}
}

// A changed byte anywhere in the signed feed is refused.
func TestVerify_TamperedFeed(t *testing.T) {
	f := newFixture(t)
	raw := f.build(t, sampleFeed(100))
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(b.Feed, &env); err != nil {
		t.Fatal(err)
	}
	var feed Feed
	payload := mustPayload(t, b.Feed)
	if err := json.Unmarshal(payload, &feed); err != nil {
		t.Fatal(err)
	}
	feed.Releases[1].Version = "v9.9.9"
	forged, _ := json.Marshal(feed)
	env["payload"] = forged // the original signature stays
	b.Feed, _ = json.Marshal(env)
	tampered, _ := json.Marshal(b)
	if _, err := Verify(tampered, f.trust, testNow); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("tampered feed: err = %v", err)
	}
}

func mustPayload(t *testing.T, env json.RawMessage) []byte {
	t.Helper()
	e, err := feedsign.Open(env, FeedPayloadType, MaxBundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	return e.Payload
}

// A feed signed by a key outside the key set, or a key set from another
// root, is refused.
func TestVerify_WrongKeys(t *testing.T) {
	f := newFixture(t)
	stranger := seedKey(9)
	raw, err := Build(f.keySet, stranger, sampleFeed(5))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(raw, f.trust, testNow); err == nil {
		t.Fatal("a feed signed outside the key set verified")
	}
	other, _ := SignKeySet(stranger, 3, testNow.Add(-time.Hour), testNow.Add(24*time.Hour), f.online.Public().(ed25519.PublicKey))
	raw, _ = Build(other, f.online, sampleFeed(5))
	if _, err := Verify(raw, f.trust, testNow); err == nil || !strings.Contains(err.Error(), "pinned root") {
		t.Fatalf("a key set of another root: err = %v", err)
	}
}

// A key set of another feed (same root, other kind) cannot stand in for the
// release key set, and a feed envelope of another payload type is refused.
func TestVerify_CrossFeedReplay(t *testing.T) {
	f := newFixture(t)
	otherType := feedsign.KeySetType{PayloadType: "application/vnd.openctem.programfeed.keyset+json", Kind: "openctem.programfeed.keyset/v1"}
	ks, _ := feedsign.SignKeySet(f.root, otherType, 3, testNow.Add(-time.Hour), testNow.Add(24*time.Hour), f.online.Public().(ed25519.PublicKey))
	raw, _ := Build(ks, f.online, sampleFeed(5))
	if _, err := Verify(raw, f.trust, testNow); err == nil {
		t.Fatal("another feed's key set verified as the release key set")
	}
	payload, _ := json.Marshal(sampleFeed(5))
	env, _ := feedsign.Sign(f.online, "application/vnd.openctem.package-index+json", payload)
	b, _ := json.Marshal(Bundle{Schema: BundleSchema, KeySet: f.keySet, Feed: env})
	if _, err := Verify(b, f.trust, testNow); err == nil || !strings.Contains(err.Error(), "payload type") {
		t.Fatalf("another payload type: err = %v", err)
	}
}

func TestVerify_Rollback(t *testing.T) {
	f := newFixture(t)
	raw := f.build(t, sampleFeed(100))
	trust := f.trust
	trust.MinSequence = 101
	if _, err := Verify(raw, trust, testNow); !errors.Is(err, ErrRollback) {
		t.Fatalf("older sequence: err = %v", err)
	}
	trust.MinSequence = 100 // the same feed again is fine
	if _, err := Verify(raw, trust, testNow); err != nil {
		t.Fatalf("same sequence: %v", err)
	}
	trust.MinKeySetVersion = 4
	if _, err := Verify(raw, trust, testNow); !errors.Is(err, ErrRollback) {
		t.Fatalf("older key set: err = %v", err)
	}
}

func TestVerify_ExpiredAndFuture(t *testing.T) {
	f := newFixture(t)
	old := sampleFeed(7)
	old.IssuedAt = testNow.Add(-40 * 24 * time.Hour)
	old.ExpiresAt = testNow.Add(-time.Minute)
	if _, err := Verify(f.build(t, old), f.trust, testNow); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: err = %v", err)
	}
	future := sampleFeed(8)
	future.IssuedAt = testNow.Add(time.Hour)
	future.ExpiresAt = testNow.Add(48 * time.Hour)
	if _, err := Verify(f.build(t, future), f.trust, testNow); err == nil {
		t.Fatal("a feed issued in the future verified")
	}
}

func TestVerify_Oversize(t *testing.T) {
	f := newFixture(t)
	big := append(f.build(t, sampleFeed(1)), bytes.Repeat([]byte(" "), MaxBundleBytes)...)
	if _, err := Verify(big, f.trust, testNow); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("oversize: err = %v", err)
	}
	if _, err := Verify(nil, f.trust, testNow); err == nil {
		t.Fatal("empty input verified")
	}
	if _, err := Verify([]byte(`{"schema":"x"}`), f.trust, testNow); err == nil {
		t.Fatal("wrong schema verified")
	}
	extra := bytes.Replace(f.build(t, sampleFeed(1)), []byte(`"schema"`), []byte(`"extra": 1, "schema"`), 1)
	if _, err := Verify(extra, f.trust, testNow); err == nil {
		t.Fatal("unknown field verified")
	}
}

func TestFeedValidate(t *testing.T) {
	cases := map[string]func(*Feed){
		"too long validity":       func(f *Feed) { f.ExpiresAt = f.IssuedAt.Add(MaxFeedValidity + time.Hour) },
		"pre-release version":     func(f *Feed) { f.Releases[0].Version = "v0.9.7-rc.1" },
		"duplicate version":       func(f *Feed) { f.Releases[1].Version = f.Releases[0].Version },
		"foreign notes link":      func(f *Feed) { f.Releases[0].NotesURL = "https://example.com/download" },
		"http link":               func(f *Feed) { f.Releases[0].NotesURL = "http://openctem.io/x" },
		"other github owner":      func(f *Feed) { f.Releases[0].NotesURL = "https://github.com/someone/openctem/releases" },
		"userinfo link":           func(f *Feed) { f.Advisories[0].URL = "https://openctem.io@example.com/" },
		"lookalike host":          func(f *Feed) { f.Advisories[0].URL = "https://openctem.io.example.com/" },
		"unknown severity":        func(f *Feed) { f.Advisories[0].Severity = "urgent" },
		"control char title":      func(f *Feed) { f.Advisories[0].Title = "fix\u0007now" },
		"long title":              func(f *Feed) { f.Advisories[0].Title = strings.Repeat("a", MaxTitle+1) },
		"introduced after fix":    func(f *Feed) { f.Advisories[0].Introduced = "v1.0.0" },
		"bad fixed_in":            func(f *Feed) { f.Advisories[0].FixedIn = "latest" },
		"bad id":                  func(f *Feed) { f.Advisories[0].ID = "../x" },
		"too many releases":       func(f *Feed) { f.Releases = make([]Release, MaxReleases+1) },
		"missing release time":    func(f *Feed) { f.Releases[0].PublishedAt = time.Time{} },
		"missing advisory time":   func(f *Feed) { f.Advisories[0].PublishedAt = time.Time{} },
		"zero sequence":           func(f *Feed) { f.Sequence = 0 },
		"expires before issued":   func(f *Feed) { f.ExpiresAt = f.IssuedAt.Add(-time.Second) },
		"duplicate advisory id":   func(f *Feed) { f.Advisories = append(f.Advisories, f.Advisories[0]) },
		"too many advisories":     func(f *Feed) { f.Advisories = make([]Advisory, MaxAdvisories+1) },
		"blank title":             func(f *Feed) { f.Advisories[0].Title = "  " },
		"link with explicit port": func(f *Feed) { f.Advisories[0].URL = "https://openctem.io:8443/x" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := sampleFeed(1)
			f.Kind = FeedKind
			mutate(&f)
			if err := f.Validate(); err == nil {
				t.Fatal("accepted")
			}
			if _, err := Build(newFixture(t).keySet, seedKey(2), f); err == nil {
				t.Fatal("the builder signed an invalid feed")
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	feed := sampleFeed(1)
	cases := []struct {
		running            string
		comparable, update bool
		newer              int
		severity, fixedIn  string
	}{
		{"v0.9.7", true, true, 1, "high", "v0.9.8"},
		{"v0.9.8", true, false, 0, "", ""},
		{"0.9.7", true, true, 1, "high", "v0.9.8"},
		{"v0.9.7-dev+abc12345", true, true, 1, "high", "v0.9.8"}, // a dev build compares as its base
		{"v0.9.8-dev.3+abc", true, false, 0, "", ""},
		{"v0.9.8-rc.1", true, true, 1, "high", "v0.9.8"}, // the final release is newer
		{"v0.8.9", true, true, 2, "", ""},                // before the advisory was introduced
		{"dev", false, false, 0, "", ""},
		{"", false, false, 0, "", ""},
	}
	for _, c := range cases {
		st := Evaluate(&feed, c.running, testNow)
		if st.Comparable != c.comparable || st.UpdateAvailable != c.update || len(st.Newer) != c.newer ||
			st.Severity != c.severity || st.FixedIn != c.fixedIn {
			t.Errorf("%q: %+v", c.running, st)
		}
		if c.comparable && st.Latest != "v0.9.8" {
			t.Errorf("%q: latest %q", c.running, st.Latest)
		}
	}
	st := Evaluate(&feed, "v0.8.0", testNow)
	if st.Newer[0].Version != "v0.9.8" {
		t.Fatalf("newer not sorted newest first: %+v", st.Newer)
	}
	if !Evaluate(&feed, "v0.9.8", feed.ExpiresAt.Add(time.Second)).Stale {
		t.Fatal("a feed past its expiry is not reported stale")
	}
	if st := Evaluate(nil, "v0.9.8", testNow); st.Comparable || st.Newer == nil || st.Advisories == nil {
		t.Fatalf("nil feed: %+v", st)
	}
}

func TestEvaluate_SeverityOrder(t *testing.T) {
	feed := sampleFeed(1)
	feed.Advisories = append(feed.Advisories, Advisory{ID: "B", Severity: "critical", Title: "b", FixedIn: "v0.9.9", PublishedAt: testNow},
		Advisory{ID: "C", Severity: "low", Title: "c", FixedIn: "v0.9.8", PublishedAt: testNow})
	st := Evaluate(&feed, "v0.9.7", testNow)
	if st.Severity != "critical" || st.FixedIn != "v0.9.9" || st.Advisories[0].ID != "B" || st.Advisories[2].ID != "C" {
		t.Fatalf("%+v", st)
	}
}
