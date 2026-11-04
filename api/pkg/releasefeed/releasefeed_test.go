package releasefeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/releasefeed/testdata/releasefeedtest"
)

// The virtual log is valid from the moment the test starts, so the clock is real.
var testNow = time.Now().UTC().Truncate(time.Second)

// fixture is a virtual Sigstore the production verifier trusts, and a signer
// that behaves like the release-feed workflow.
type fixture struct {
	sig   *releasefeedtest.Sigstore
	trust Trust
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sig := releasefeedtest.New(t)
	return &fixture{sig: sig, trust: Trust{Verifier: sig.Verifier(t)}}
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
		Components: []Component{
			{Component: "sensor", Version: "v0.23.2", PublishedAt: testNow.Add(-48 * time.Hour),
				NotesURL: "https://github.com/openctemio/sensor/releases/tag/v0.23.2", Digest: "sha256:" + strings.Repeat("ab", 32)},
			{Component: "sdk", Version: "v0.34.0", PublishedAt: testNow.Add(-48 * time.Hour)},
		},
	}
}

// signedAt is when the workflow signs in the tests: a minute after testNow,
// inside the validity of the virtual certificate (made at the real time).
func signedAt(Feed) time.Time { return testNow.Add(time.Minute) }

func (f *fixture) publish(t *testing.T, feed Feed, identity, issuer string, at time.Time, withoutTlog bool) []byte {
	t.Helper()
	payload, err := Payload(feed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Assemble(payload, f.sig.Sign(t, payload, identity, issuer, at, withoutTlog))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) build(t *testing.T, feed Feed) []byte {
	t.Helper()
	return f.publish(t, feed, releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer, signedAt(feed), false)
}

func TestVerify_Valid(t *testing.T) {
	f := newFixture(t)
	for _, id := range []string{releasefeedtest.GoodIdentityMain, releasefeedtest.GoodIdentityTag} {
		feed := sampleFeed(100)
		v, err := Verify(f.publish(t, feed, id, releasefeedtest.GitHubIssuer, signedAt(feed), false), f.trust, testNow)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if v.Feed.Sequence != 100 || len(v.Feed.Releases) != 2 || len(v.Digest) != 64 || !v.SignedAt.Equal(signedAt(feed)) {
			t.Fatalf("verified = %+v", v)
		}
	}
}

func TestVerify_InertWithoutVerifier(t *testing.T) {
	f := newFixture(t)
	if _, err := Verify(f.build(t, sampleFeed(1)), Trust{}, testNow); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no verifier: err = %v", err)
	}
}

// Only the release-feed workflow of this repository on main or a release tag,
// from the GitHub issuer, is accepted.
func TestVerify_SignerIdentity(t *testing.T) {
	f := newFixture(t)
	feed := sampleFeed(5)
	wf := "https://github.com/openctemio/openctem/.github/workflows/release-feed.yml@"
	cases := map[string]struct{ id, issuer string }{
		"another repository": {"https://github.com/evil/openctem/.github/workflows/release-feed.yml@refs/heads/main", releasefeedtest.GitHubIssuer},
		"similar repository": {"https://github.com/openctemio/openctem-fork/.github/workflows/release-feed.yml@refs/heads/main", releasefeedtest.GitHubIssuer},
		"another workflow":   {"https://github.com/openctemio/openctem/.github/workflows/release.yml@refs/heads/main", releasefeedtest.GitHubIssuer},
		"another branch":     {wf + "refs/heads/feature", releasefeedtest.GitHubIssuer},
		"pull request ref":   {wf + "refs/pull/1/merge", releasefeedtest.GitHubIssuer},
		"suffix on the tag":  {wf + "refs/tags/v1.2.3-evil/x", releasefeedtest.GitHubIssuer},
		"prefix on the url":  {"x" + wf + "refs/heads/main", releasefeedtest.GitHubIssuer},
		"another issuer":     {releasefeedtest.GoodIdentityMain, "https://accounts.example.com"},
		"issuer lookalike":   {releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer + ".evil"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(f.publish(t, feed, c.id, c.issuer, signedAt(feed), false), f.trust, testNow); err == nil || !strings.Contains(err.Error(), "signature") {
				t.Fatalf("accepted: err = %v", err)
			}
		})
	}
}

// A feed another Sigstore signed (a foreign trusted root) is refused, and so
// is one the verifier's root does not know.
func TestVerify_ForeignTrustedRoot(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	if _, err := Verify(other.build(t, sampleFeed(5)), f.trust, testNow); err == nil {
		t.Fatal("a feed signed under a foreign trusted root verified")
	}
}

// The signing certificate is short-lived: a signature whose log time is long
// after the certificate expired is refused.
func TestVerify_ExpiredCertificate(t *testing.T) {
	f := newFixture(t)
	feed := sampleFeed(5)
	raw := f.publish(t, feed, releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer, testNow.Add(3*time.Hour), false)
	if _, err := Verify(raw, f.trust, testNow); err == nil {
		t.Fatal("a signature logged after its certificate expired verified")
	}
}

func TestVerify_MissingTlogEntry(t *testing.T) {
	f := newFixture(t)
	feed := sampleFeed(5)
	raw := f.publish(t, feed, releasefeedtest.GoodIdentityMain, releasefeedtest.GitHubIssuer, signedAt(feed), true)
	if _, err := Verify(raw, f.trust, testNow); err == nil {
		t.Fatal("a bundle without a transparency log entry verified")
	}
}

// A signature made before the feed was issued, or after it expired, is not
// the publisher's feed.
func TestVerify_SignedOutsideValidity(t *testing.T) {
	f := newFixture(t)
	early := sampleFeed(5)
	early.IssuedAt, early.ExpiresAt = testNow.Add(time.Hour), testNow.Add(30*24*time.Hour)
	if _, err := Verify(f.build(t, early), f.trust, testNow.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("signed before issue: err = %v", err)
	}
	late := sampleFeed(6)
	late.IssuedAt, late.ExpiresAt = testNow.Add(-time.Hour), testNow.Add(30*time.Second)
	if _, err := Verify(f.build(t, late), f.trust, testNow); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("signed after expiry: err = %v", err)
	}
}

func TestVerify_TamperedFeed(t *testing.T) {
	f := newFixture(t)
	raw := f.build(t, sampleFeed(100))
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.Feed = bytes.Replace(b.Feed, []byte("v0.9.8"), []byte("v9.9.9"), 1) // the original signature stays
	tampered, _ := json.Marshal(b)
	if _, err := Verify(tampered, f.trust, testNow); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered feed: err = %v", err)
	}
}

// Another feed's signature pasted onto this one does not verify either.
func TestVerify_SwappedSignature(t *testing.T) {
	f := newFixture(t)
	var a, b Bundle
	_ = json.Unmarshal(f.build(t, sampleFeed(100)), &a)
	_ = json.Unmarshal(f.build(t, sampleFeed(101)), &b)
	a.Signature = b.Signature
	swapped, _ := json.Marshal(a)
	if _, err := Verify(swapped, f.trust, testNow); err == nil {
		t.Fatal("a swapped signature verified")
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
		"component name":          func(f *Feed) { f.Components[0].Component = "Sensor/../x" },
		"duplicate component":     func(f *Feed) { f.Components[1].Component = f.Components[0].Component },
		"component version":       func(f *Feed) { f.Components[0].Version = "latest" },
		"component pre-release":   func(f *Feed) { f.Components[0].Version = "v0.24.0-rc.1" },
		"component time":          func(f *Feed) { f.Components[0].PublishedAt = time.Time{} },
		"component digest":        func(f *Feed) { f.Components[0].Digest = "sha256:XYZ" },
		"component digest algo":   func(f *Feed) { f.Components[0].Digest = "md5:" + strings.Repeat("a", 32) },
		"component foreign link":  func(f *Feed) { f.Components[0].NotesURL = "https://example.com/sensor" },
		"too many components":     func(f *Feed) { f.Components = make([]Component, MaxComponents+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := sampleFeed(1)
			f.Kind = FeedKind
			mutate(&f)
			if err := f.Validate(); err == nil {
				t.Fatal("accepted")
			}
			if _, err := Payload(f); err == nil {
				t.Fatal("the builder produced an invalid feed")
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

// The components survive signing and verification, and the map view keys
// them by name.
func TestVerify_Components(t *testing.T) {
	f := newFixture(t)
	v, err := Verify(f.build(t, sampleFeed(7)), f.trust, testNow)
	if err != nil {
		t.Fatal(err)
	}
	cv := v.Feed.ComponentVersions()
	if cv["sensor"].Version != "v0.23.2" || cv["sensor"].Digest == "" || cv["sdk"].Version != "v0.34.0" || len(cv) != 2 {
		t.Fatalf("components = %+v", cv)
	}
	var nilFeed *Feed
	if nilFeed.ComponentVersions() != nil || (&Feed{}).ComponentVersions() != nil {
		t.Fatal("no components must map to nil")
	}
}

// A feed without components (the format before them) still verifies.
func TestVerify_NoComponents(t *testing.T) {
	f := newFixture(t)
	feed := sampleFeed(8)
	feed.Components = nil
	v, err := Verify(f.build(t, feed), f.trust, testNow)
	if err != nil || len(v.Feed.Components) != 0 {
		t.Fatalf("v = %+v, err = %v", v, err)
	}
}
