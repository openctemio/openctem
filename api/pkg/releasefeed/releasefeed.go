// Package releasefeed reads and writes the signed release feed: the list of
// OpenCTEM releases and security advisories an instance compares with its own
// version (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md).
//
// The feed is one DSSE envelope (the shared signed-feed envelope, pkg/feedsign)
// signed directly by one online Ed25519 key whose public key is pinned in this
// release (PinnedKeys, two entries at most so a rotation can overlap).
// Verification: a pinned key signed it, the feed sequence never below the one
// applied, the feed not expired and valid for at most 45 days, every field
// bounded and every link under our own hosts. The feed is information only:
// nothing is downloaded or run because of it.
//
// The feed has its own DSSE payload type (FeedPayloadType), so the same online
// key may also sign other content (the content catalog) without a signature
// over one ever being valid as the other.
package releasefeed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/semver"

	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Format constants (must match the builder, cmd/release-feed).
const (
	BundleSchema      = "openctem.io/release-bundle/v1"
	FeedPayloadType   = "application/vnd.openctem.release-feed+json"
	FeedKind          = "openctem.io/release-feed/v1"
	// FileName is the published file.
	FileName = "openctem-releases.json"
)

// Bounds.
const (
	MaxBundleBytes  = 256 << 10
	MaxFeedValidity = 45 * 24 * time.Hour
	MaxPinnedKeys   = 2
	MaxReleases     = 200
	MaxAdvisories   = 200
	MaxTitle        = 200
	MaxURL          = 512
)

// Severities of an advisory, lowest first.
var Severities = []string{"low", "medium", "high", "critical"}

// PinnedKeys are the Ed25519 public keys (hex, 64 characters) this release
// trusts to sign the release feed: the online key, plus the next one while a
// rotation overlaps (at most MaxPinnedKeys). Empty: nothing verifies and the
// version check stays inert. Changed only by a reviewed commit, never by
// configuration.
var PinnedKeys = []string{}

// Errors a caller tells apart.
var (
	ErrNoKey    = errors.New("no release feed key is pinned in this build")
	ErrRollback = errors.New("older than the release feed already applied")
	ErrExpired  = errors.New("the release feed has expired")
)

// Release is one published release.
type Release struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	NotesURL    string    `json:"notes_url,omitempty"`
}

// Advisory is one published security advisory. It affects a version v when
// Introduced <= v < FixedIn (Introduced optional).
type Advisory struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Introduced  string    `json:"introduced,omitempty"`
	FixedIn     string    `json:"fixed_in"`
	PublishedAt time.Time `json:"published_at"`
	URL         string    `json:"url,omitempty"`
}

// Feed is the signed release feed.
type Feed struct {
	Kind       string     `json:"kind"`
	Sequence   uint64     `json:"sequence"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Releases   []Release  `json:"releases"`
	Advisories []Advisory `json:"advisories"`
}

// Bundle is the published file: the signed feed envelope.
type Bundle struct {
	Schema string          `json:"schema"`
	Feed   json.RawMessage `json:"feed"`
}

// Trust is what an instance pins and has applied.
type Trust struct {
	// Keys are the pinned public keys, hex (releasefeed.PinnedKeys in production).
	Keys        []string
	MinSequence uint64
}

// Verified is a feed that passed every check. Digest is the SHA-256 (hex)
// of the signed feed payload: an instance accepts the same sequence again
// only with the same digest.
type Verified struct {
	Feed Feed
	// KeyID is the id (jobsign.KeyID) of the pinned key that signed it.
	KeyID  string
	Digest string
}

// pinnedKeys decodes the pinned keys; a malformed or surplus entry is an
// error (a bad pin must not silently verify less than intended).
func pinnedKeys(hexKeys []string) ([]ed25519.PublicKey, error) {
	if len(hexKeys) > MaxPinnedKeys {
		return nil, fmt.Errorf("release feed: more than %d pinned keys", MaxPinnedKeys)
	}
	out := make([]ed25519.PublicKey, 0, len(hexKeys))
	for _, h := range hexKeys {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("release feed: a pinned key is not a hex Ed25519 public key")
		}
		out = append(out, b)
	}
	return out, nil
}

// Verify checks a published file at now and returns its feed.
func Verify(raw []byte, t Trust, now time.Time) (*Verified, error) {
	if len(t.Keys) == 0 {
		return nil, ErrNoKey
	}
	keys, err := pinnedKeys(t.Keys)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("release feed: empty or over %d bytes", MaxBundleBytes)
	}
	var b Bundle
	if err := feedsign.DecodeStrict(raw, &b); err != nil {
		return nil, fmt.Errorf("release feed: %w", err)
	}
	if b.Schema != BundleSchema {
		return nil, fmt.Errorf("release feed: schema %q", b.Schema)
	}
	env, err := feedsign.Open(b.Feed, FeedPayloadType, MaxBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("release feed: %w", err)
	}
	var signer ed25519.PublicKey
	for _, k := range keys {
		if feedsign.VerifiedBy(env, k) {
			signer = k
			break
		}
	}
	if signer == nil {
		return nil, errors.New("release feed: not signed by a pinned key")
	}
	var f Feed
	if err := feedsign.DecodeStrict(env.Payload, &f); err != nil {
		return nil, fmt.Errorf("release feed: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if f.Sequence < t.MinSequence {
		return nil, fmt.Errorf("%w: sequence %d is below %d", ErrRollback, f.Sequence, t.MinSequence)
	}
	if f.IssuedAt.After(now.Add(feedsign.MaxClockSkew)) {
		return nil, errors.New("release feed: issued in the future")
	}
	if !f.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w at %s", ErrExpired, f.ExpiresAt.UTC().Format(time.RFC3339))
	}
	sum := sha256.Sum256(env.Payload)
	return &Verified{Feed: f, KeyID: jobsign.KeyID(signer), Digest: hex.EncodeToString(sum[:])}, nil
}

var (
	releaseVersion = regexp.MustCompile(`^v\d{1,4}\.\d{1,4}\.\d{1,6}$`)
	advisoryID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
)

// Validate checks the feed's structure and bounds (not the clock).
func (f *Feed) Validate() error {
	switch {
	case f.Kind != FeedKind:
		return fmt.Errorf("release feed: kind %q", f.Kind)
	case f.Sequence == 0:
		return errors.New("release feed: sequence")
	case f.IssuedAt.IsZero() || !f.ExpiresAt.After(f.IssuedAt) || f.ExpiresAt.Sub(f.IssuedAt) > MaxFeedValidity:
		return fmt.Errorf("release feed: validity must be at most %s", MaxFeedValidity)
	case len(f.Releases) > MaxReleases:
		return fmt.Errorf("release feed: over %d releases", MaxReleases)
	case len(f.Advisories) > MaxAdvisories:
		return fmt.Errorf("release feed: over %d advisories", MaxAdvisories)
	}
	seen := map[string]bool{}
	for _, r := range f.Releases {
		if !releaseVersion.MatchString(r.Version) || seen[r.Version] || r.PublishedAt.IsZero() {
			return fmt.Errorf("release feed: release %q", r.Version)
		}
		if err := checkURL(r.NotesURL); err != nil {
			return fmt.Errorf("release feed: release %s: %w", r.Version, err)
		}
		seen[r.Version] = true
	}
	ids := map[string]bool{}
	for _, a := range f.Advisories {
		switch {
		case !advisoryID.MatchString(a.ID) || ids[a.ID]:
			return fmt.Errorf("release feed: advisory id %q", a.ID)
		case !slices.Contains(Severities, a.Severity):
			return fmt.Errorf("release feed: advisory %s: severity %q", a.ID, a.Severity)
		case checkText(a.Title) != nil:
			return fmt.Errorf("release feed: advisory %s: title", a.ID)
		case !releaseVersion.MatchString(a.FixedIn):
			return fmt.Errorf("release feed: advisory %s: fixed_in %q", a.ID, a.FixedIn)
		case a.Introduced != "" && (!releaseVersion.MatchString(a.Introduced) || semver.Compare(a.Introduced, a.FixedIn) >= 0):
			return fmt.Errorf("release feed: advisory %s: introduced %q", a.ID, a.Introduced)
		case a.PublishedAt.IsZero():
			return fmt.Errorf("release feed: advisory %s: published_at", a.ID)
		}
		if err := checkURL(a.URL); err != nil {
			return fmt.Errorf("release feed: advisory %s: %w", a.ID, err)
		}
		ids[a.ID] = true
	}
	return nil
}

func checkText(s string) error {
	if strings.TrimSpace(s) == "" || len(s) > MaxTitle {
		return errors.New("text")
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return errors.New("text")
		}
	}
	return nil
}

// checkURL allows an empty link or an https link under our own hosts.
func checkURL(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > MaxURL {
		return errors.New("link too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return errors.New("link must be https")
	}
	switch u.Host {
	case "openctem.io", "docs.openctem.io":
		return nil
	case "github.com":
		if strings.HasPrefix(u.Path, "/openctemio/") {
			return nil
		}
	}
	return fmt.Errorf("link host %q is not allowed", u.Host)
}

// Build signs f with the online key and returns the file to publish (the
// builder and tests; an instance never holds a feed key).
func Build(online ed25519.PrivateKey, f Feed) ([]byte, error) {
	f.Kind = FeedKind
	if err := f.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	env, err := feedsign.Sign(online, FeedPayloadType, payload)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(Bundle{Schema: BundleSchema, Feed: env}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(out) > MaxBundleBytes {
		return nil, fmt.Errorf("release feed: over %d bytes", MaxBundleBytes)
	}
	return out, nil
}
