package contentpkg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Signed document types. Each has its own DSSE payload type and kind, so a
// signature over one can never be replayed as another.
const (
	KeySetPayloadType      = "application/vnd.openctem.catalog-keyset+json"
	KeySetKind             = "openctem.io/catalog-keyset/v1"
	StatementPayloadType   = "application/vnd.openctem.package-statement+json"
	StatementKind          = "openctem.io/package-statement/v1"
	IndexPayloadType       = "application/vnd.openctem.package-index+json"
	IndexKind              = "openctem.io/package-index/v1"
	RevocationsPayloadType = "application/vnd.openctem.package-revocations+json"
	RevocationsKind        = "openctem.io/package-revocations/v1"
)

// Validity bounds.
const (
	MaxIndexValidity       = 90 * 24 * time.Hour
	MaxRevocationsValidity = 30 * 24 * time.Hour
	maxStatementBytes      = 16 << 10
	maxIndexBytes          = 4 << 20
	maxRevocationsBytes    = 4 << 20
	MaxIndexEntries        = 4096
	MaxRevocationEntries   = 8192
)

// KeySetType is the catalog key set: the feed key set format under the
// catalog's own payload type and kind.
var KeySetType = feedsign.KeySetType{PayloadType: KeySetPayloadType, Kind: KeySetKind}

// Origins of a package.
const (
	OriginFirstParty   = "first-party"
	OriginCatalog      = "catalog"
	OriginInstance     = "instance"
	OriginOrganization = "organization"
)

// Publisher is the identity that signed the artifact.
type Publisher struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
}

// Statement is the catalog countersignature of one package version: what
// was reviewed. Every field must equal the manifest.
type Statement struct {
	Kind           string      `json:"kind"`
	ID             string      `json:"id"`
	Version        string      `json:"version"`
	Type           Type        `json:"type"`
	ManifestDigest string      `json:"manifest_digest"`
	Artifact       Artifact    `json:"artifact"`
	Permissions    Permissions `json:"permissions"`
	License        License     `json:"license"`
	Publisher      Publisher   `json:"publisher"`
	Origin         string      `json:"origin"`
	ReviewedAt     time.Time   `json:"reviewed_at"`
}

// NewStatement is the statement of a manifest (what a signer signs).
func NewStatement(m *Manifest, manifestRaw []byte, origin string, reviewedAt time.Time) Statement {
	return Statement{
		Kind: StatementKind, ID: m.ID, Version: m.Version, Type: m.Type,
		ManifestDigest: Digest(manifestRaw), Artifact: m.Artifact, Permissions: m.Permissions,
		License:   m.License,
		Publisher: Publisher{Identity: m.Provenance.BuildIdentity, Issuer: m.Provenance.BuildIssuer},
		Origin:    origin, ReviewedAt: reviewedAt.UTC(),
	}
}

// Matches checks st against the manifest and its exact bytes.
func (st *Statement) Matches(m *Manifest, manifestRaw []byte) error {
	want := NewStatement(m, manifestRaw, st.Origin, st.ReviewedAt)
	got := *st
	got.ReviewedAt = got.ReviewedAt.UTC()
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if !bytes.Equal(a, b) {
		return errors.New("the catalog statement does not match the manifest")
	}
	switch st.Origin {
	case OriginFirstParty:
		if !IsReservedNamespace(m.Namespace()) {
			return errors.New("a first-party statement for a namespace that is not reserved")
		}
	case OriginCatalog, OriginInstance, OriginOrganization:
		if IsReservedNamespace(m.Namespace()) {
			return fmt.Errorf("namespace %q is reserved for first-party packages", m.Namespace())
		}
	default:
		return fmt.Errorf("unknown origin %q", st.Origin)
	}
	if st.ReviewedAt.IsZero() {
		return errors.New("the catalog statement has no review time")
	}
	return nil
}

// IndexEntry is one package version a bundle carries.
type IndexEntry struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
	ArtifactDigest string `json:"artifact_digest"`
}

// Index is the signed list of what a bundle carries, with a sequence (no
// rollback) and an expiry (no freeze).
type Index struct {
	Kind      string       `json:"kind"`
	Sequence  uint64       `json:"sequence"`
	IssuedAt  time.Time    `json:"issued_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Packages  []IndexEntry `json:"packages"`
}

// RevocationEntry names what is revoked: a package id (every version), an
// id and a version, or an artifact digest.
type RevocationEntry struct {
	ID        string    `json:"id,omitempty"`
	Version   string    `json:"version,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Reason    string    `json:"reason"`
	Severity  string    `json:"severity"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Revocations is the signed revocation list: a full snapshot.
type Revocations struct {
	Kind      string            `json:"kind"`
	Sequence  uint64            `json:"sequence"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Entries   []RevocationEntry `json:"entries"`
}

// Matches reports whether e revokes the package version.
func (e RevocationEntry) Matches(id, version, artifactDigest string) bool {
	switch {
	case e.Digest != "":
		return e.Digest == artifactDigest
	case e.Version != "":
		return e.ID == id && e.Version == version
	default:
		return e.ID == id
	}
}

// RevokedBy returns the first entry that revokes the package version.
func RevokedBy(entries []RevocationEntry, id, version, artifactDigest string) (RevocationEntry, bool) {
	for _, e := range entries {
		if e.Matches(id, version, artifactDigest) {
			return e, true
		}
	}
	return RevocationEntry{}, false
}

var severities = []string{"low", "medium", "high", "critical"}

func (r *Revocations) validate() error {
	if len(r.Entries) > MaxRevocationEntries {
		return fmt.Errorf("revocation list: over %d entries", MaxRevocationEntries)
	}
	for i, e := range r.Entries {
		named := 0
		if e.Digest != "" {
			named++
			if !digestPattern.MatchString(e.Digest) || e.ID != "" || e.Version != "" {
				return fmt.Errorf("revocation entry %d: a digest entry names only the digest", i)
			}
		}
		if e.ID != "" {
			named++
			if !ValidID(e.ID) {
				return fmt.Errorf("revocation entry %d: id", i)
			}
			if e.Version != "" {
				if _, err := ParseVersion(e.Version); err != nil {
					return fmt.Errorf("revocation entry %d: %w", i, err)
				}
			}
		}
		if named != 1 {
			return fmt.Errorf("revocation entry %d names nothing", i)
		}
		if !slices.Contains(severities, e.Severity) || strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 500 ||
			checkText("reason", e.Reason, 500, false) != nil || e.RevokedAt.IsZero() {
			return fmt.Errorf("revocation entry %d: severity, reason and time are required", i)
		}
	}
	return nil
}

func checkWindow(what string, issued, expires time.Time, maxValidity time.Duration) error {
	if issued.IsZero() || !expires.After(issued) || expires.Sub(issued) > maxValidity {
		return fmt.Errorf("%s: validity must be at most %s", what, maxValidity)
	}
	return nil
}

// Trust is what an instance pins and has applied.
type Trust struct {
	// Roots are the key ids of the offline catalog roots this release
	// trusts. Empty: nothing verifies.
	Roots []string
	// MinKeySetVersion is the last applied key set version.
	MinKeySetVersion uint64
}

// VerifyKeySet checks the catalog key set against any pinned root.
func (t Trust) VerifyKeySet(raw []byte, now time.Time) (*feedsign.KeySet, error) {
	if len(t.Roots) == 0 {
		return nil, errors.New("no catalog root is configured")
	}
	var lastErr error
	for _, root := range t.Roots {
		ks, err := feedsign.VerifyKeySet(raw, KeySetType, root, t.MinKeySetVersion, now)
		if err == nil {
			return ks, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// verifyStatement checks a statement envelope with the key set.
func verifyStatement(ks *feedsign.KeySet, raw []byte) (*Statement, error) {
	var st Statement
	if err := feedsign.VerifyWith(ks, raw, StatementPayloadType, maxStatementBytes, &st); err != nil {
		return nil, fmt.Errorf("catalog statement: %w", err)
	}
	if st.Kind != StatementKind {
		return nil, errors.New("catalog statement: unknown kind")
	}
	return &st, nil
}

// VerifyIndex checks the index envelope with the key set and its window at
// now.
func VerifyIndex(ks *feedsign.KeySet, raw []byte, now time.Time) (*Index, error) {
	var ix Index
	if err := feedsign.VerifyWith(ks, raw, IndexPayloadType, maxIndexBytes, &ix); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if ix.Kind != IndexKind || ix.Sequence == 0 {
		return nil, errors.New("index: kind or sequence")
	}
	if err := checkWindow("index", ix.IssuedAt, ix.ExpiresAt, MaxIndexValidity); err != nil {
		return nil, err
	}
	if ix.IssuedAt.After(now.Add(feedsign.MaxClockSkew)) {
		return nil, errors.New("index: issued in the future")
	}
	if !ix.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: index expired at %s", ErrExpired, ix.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if len(ix.Packages) > MaxIndexEntries {
		return nil, fmt.Errorf("index: over %d packages", MaxIndexEntries)
	}
	seen := map[string]bool{}
	for _, e := range ix.Packages {
		key := e.ID + "@" + e.Version
		if !ValidID(e.ID) || seen[key] || !digestPattern.MatchString(e.ManifestDigest) || !digestPattern.MatchString(e.ArtifactDigest) {
			return nil, fmt.Errorf("index: entry %q", key)
		}
		if _, err := ParseVersion(e.Version); err != nil {
			return nil, fmt.Errorf("index: entry %q: %w", key, err)
		}
		seen[key] = true
	}
	return &ix, nil
}

// VerifyRevocations checks the revocation list envelope with the key set.
// An expired list verifies (Stale reports it): an air-gapped instance keeps
// applying the newest list it has.
func VerifyRevocations(ks *feedsign.KeySet, raw []byte, now time.Time) (*Revocations, error) {
	var rv Revocations
	if err := feedsign.VerifyWith(ks, raw, RevocationsPayloadType, maxRevocationsBytes, &rv); err != nil {
		return nil, fmt.Errorf("revocation list: %w", err)
	}
	if rv.Kind != RevocationsKind || rv.Sequence == 0 {
		return nil, errors.New("revocation list: kind or sequence")
	}
	if err := checkWindow("revocation list", rv.IssuedAt, rv.ExpiresAt, MaxRevocationsValidity); err != nil {
		return nil, err
	}
	if rv.IssuedAt.After(now.Add(feedsign.MaxClockSkew)) {
		return nil, errors.New("revocation list: issued in the future")
	}
	if err := rv.validate(); err != nil {
		return nil, err
	}
	return &rv, nil
}

// Stale reports whether the revocation list is past its expiry at now.
func (r *Revocations) Stale(now time.Time) bool { return !r.ExpiresAt.After(now) }

// ErrExpired: signed metadata is past its expiry.
var ErrExpired = errors.New("expired")

// Sign signs a document as a DSSE envelope with an online key (the
// first-party generator and tests; an instance never holds a catalog key).
func Sign(priv ed25519.PrivateKey, payloadType string, v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return feedsign.Sign(priv, payloadType, payload)
}
