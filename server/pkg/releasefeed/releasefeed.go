// Package releasefeed reads and writes the signed release feed: the list of
// OpenCTEM releases and security advisories an instance compares with its own
// version (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md), and the
// newest release of each first-party component (sensor products, sdk-go),
// which an instance uses instead of the version built into it
// (docs/rfcs/RFC-037-versioning-and-release-train.md §12).
//
// The published file holds the feed payload and a keyless Sigstore bundle
// over its exact bytes (`cosign sign-blob --bundle`), made by the release-feed
// workflow with its GitHub OIDC identity: there is no long-lived signing key.
// An instance verifies offline (SignatureVerifier, backed by the Sigstore trusted
// root embedded in the release): the certificate chain to the Fulcio roots, a
// transparency log entry, the issuer (GitHub Actions) and the exact signer
// identity (SignerIdentityPattern: the release-feed workflow of this
// repository on main or a release tag).
// Then: the feed sequence never below the one applied, the feed not expired and
// valid for at most 45 days, the signature made inside the feed's validity,
// every field bounded and every link under our own hosts. The feed is
// information only: nothing is downloaded or run because of it.
package releasefeed

import (
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

	"github.com/openctemio/openctem/server/pkg/feedsign"
)

// Format constants (must match the builder, cmd/release-feed).
const (
	BundleSchema = "openctem.io/release-bundle/v2"
	FeedKind     = "openctem.io/release-feed/v1"
	// FileName is the published file.
	FileName = "openctem-releases.json"
)

// Bounds.
const (
	MaxBundleBytes  = 256 << 10
	MaxFeedValidity = 45 * 24 * time.Hour
	MaxReleases     = 200
	MaxAdvisories   = 200
	MaxComponents   = 32
	MaxTitle        = 200
	MaxURL          = 512
)

// Severities of an advisory, lowest first.
var Severities = []string{"low", "medium", "high", "critical"}

// Who may sign the feed: the release-feed workflow of this repository, run
// from main or a release tag, authenticated by GitHub Actions' OIDC issuer. A
// workflow of another repository, another file, a fork or another branch is
// refused whatever it signs. Changed only by a reviewed commit.
const (
	SignerIssuer          = "https://token.actions.githubusercontent.com"
	SignerIdentityPattern = `^https://github\.com/openctemio/openctem/\.github/workflows/release-feed\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$`
)

// SignatureVerifier checks a keyless Sigstore bundle over artifact offline and
// returns when it was signed (contentpkg/sigstore.Verifier).
type SignatureVerifier interface {
	VerifyPattern(signature, artifact []byte, identityPattern, issuer string) (time.Time, error)
}

// Errors a caller tells apart.
var (
	ErrNoKey    = errors.New("no Sigstore trusted root is loaded to verify the release feed")
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

// Component is the newest stable release of one first-party component: a
// sensor product or the SDK, named by its section in versions.yaml
// ("sensor", "connector-tenable", "sdk"). Digest is the image manifest digest
// of that release ("sha256:<hex>") for a component that ships an image. The
// image repository is never taken from the feed: it comes from the catalog
// built into the instance.
type Component struct {
	Component   string    `json:"component"`
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	NotesURL    string    `json:"notes_url,omitempty"`
	Digest      string    `json:"digest,omitempty"`
}

// Feed is the signed release feed.
type Feed struct {
	Kind       string      `json:"kind"`
	Sequence   uint64      `json:"sequence"`
	IssuedAt   time.Time   `json:"issued_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Releases   []Release   `json:"releases"`
	Advisories []Advisory  `json:"advisories"`
	Components []Component `json:"components,omitempty"`
}

// ComponentVersions maps each component the feed lists to its release.
func (f *Feed) ComponentVersions() map[string]Component {
	if f == nil || len(f.Components) == 0 {
		return nil
	}
	out := make(map[string]Component, len(f.Components))
	for _, c := range f.Components {
		out[c.Component] = c
	}
	return out
}

// Bundle is the published file: the feed payload (base64 of its exact bytes,
// which the signature covers) and the Sigstore bundle over them.
type Bundle struct {
	Schema    string          `json:"schema"`
	Feed      []byte          `json:"feed"`
	Signature json.RawMessage `json:"signature"`
}

// Trust is what an instance trusts and has applied.
type Trust struct {
	// Verifier checks the Sigstore bundle; nil refuses every feed (ErrNoKey).
	Verifier    SignatureVerifier
	MinSequence uint64
}

// Verified is a feed that passed every check. Digest is the SHA-256 (hex)
// of the signed feed payload: an instance accepts the same sequence again
// only with the same digest. SignedAt is the transparency log time of the
// signature.
type Verified struct {
	Feed     Feed
	SignedAt time.Time
	Digest   string
}

// Verify checks a published file at now and returns its feed.
func Verify(raw []byte, t Trust, now time.Time) (*Verified, error) {
	if t.Verifier == nil {
		return nil, ErrNoKey
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
	signedAt, err := t.Verifier.VerifyPattern(b.Signature, b.Feed, SignerIdentityPattern, SignerIssuer)
	if err != nil {
		return nil, fmt.Errorf("release feed: signature: %w", err)
	}
	var f Feed
	if err := feedsign.DecodeStrict(b.Feed, &f); err != nil {
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
	// The signature was made while the feed was current: a signature older
	// than the feed, or after it expired, is not the publisher's.
	if signedAt.Before(f.IssuedAt.Add(-feedsign.MaxClockSkew)) || signedAt.After(f.ExpiresAt) {
		return nil, errors.New("release feed: signed outside the feed's validity")
	}
	sum := sha256.Sum256(b.Feed)
	return &Verified{Feed: f, SignedAt: signedAt, Digest: hex.EncodeToString(sum[:])}, nil
}

var (
	releaseVersion = regexp.MustCompile(`^v\d{1,4}\.\d{1,4}\.\d{1,6}$`)
	advisoryID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	componentName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	imageDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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
	case len(f.Components) > MaxComponents:
		return fmt.Errorf("release feed: over %d components", MaxComponents)
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
	return validateComponents(f.Components)
}

func validateComponents(cs []Component) error {
	names := map[string]bool{}
	for _, c := range cs {
		switch {
		case !componentName.MatchString(c.Component) || names[c.Component]:
			return fmt.Errorf("release feed: component %q", c.Component)
		case !releaseVersion.MatchString(c.Version):
			return fmt.Errorf("release feed: component %s: version %q", c.Component, c.Version)
		case c.PublishedAt.IsZero():
			return fmt.Errorf("release feed: component %s: published_at", c.Component)
		case c.Digest != "" && !imageDigest.MatchString(c.Digest):
			return fmt.Errorf("release feed: component %s: digest", c.Component)
		}
		if err := checkURL(c.NotesURL); err != nil {
			return fmt.Errorf("release feed: component %s: %w", c.Component, err)
		}
		names[c.Component] = true
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

// Payload validates f and returns the exact bytes the workflow signs with
// cosign (the builder and tests; an instance never produces a feed).
func Payload(f Feed) ([]byte, error) {
	f.Kind = FeedKind
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(f)
}

// Assemble returns the file to publish: payload with its Sigstore bundle.
func Assemble(payload, sigstoreBundle []byte) ([]byte, error) {
	if !json.Valid(sigstoreBundle) {
		return nil, errors.New("release feed: the Sigstore bundle is not JSON")
	}
	out, err := json.MarshalIndent(Bundle{Schema: BundleSchema, Feed: payload, Signature: sigstoreBundle}, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(out) > MaxBundleBytes {
		return nil, fmt.Errorf("release feed: over %d bytes", MaxBundleBytes)
	}
	return out, nil
}
