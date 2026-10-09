// Package contentpack is the domain of content packs: immutable,
// content-addressed archives of templates, rules, wordlists and other tool
// content that the platform lints, classifies and signs before any sensor
// uses them. Design and threat model: docs/rfcs/RFC-061-content-packs.md.
package contentpack

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Tier is how intrusive a pack's content is, the same scale as tool tiers:
// T0 passive, T1 active, T2 intrusive.
type Tier string

// Tiers.
const (
	TierT0 Tier = "T0"
	TierT1 Tier = "T1"
	TierT2 Tier = "T2"
)

// Rank orders tiers (T0 < T1 < T2).
func (t Tier) Rank() int {
	switch t {
	case TierT0:
		return 0
	case TierT1:
		return 1
	default:
		return 2
	}
}

// Max is the more intrusive of t and o.
func (t Tier) Max(o Tier) Tier {
	if o.Rank() > t.Rank() {
		return o
	}
	return t
}

// Status is a pack's state. A pack never changes after it is stored; it can
// only be revoked.
type Status string

// Statuses.
const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// Source is where a pack came from.
type Source string

// Sources. Only uploads exist today; the others are RFC-061 §3.6 sources.
const (
	SourceUpload Source = "upload"
)

// Known kinds: the ones the platform lints. Any other plain kind is refused;
// a namespaced kind (x-<namespace>/<kind>) is accepted, unlinted and
// classified T1.
const (
	KindNucleiTemplates = "nuclei-templates"
	KindSemgrepRules    = "semgrep-rules"
	KindWordlist        = "wordlist"
)

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	kindPattern    = regexp.MustCompile(`^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}/[a-z][a-z0-9-]{1,40})$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Errors.
var (
	ErrNotFound      = fmt.Errorf("%w: content pack not found", shared.ErrNotFound)
	ErrExists        = fmt.Errorf("%w: a content pack with this name and version exists", shared.ErrConflict)
	ErrNotActive     = fmt.Errorf("%w: the content pack is already revoked", shared.ErrConflict)
	ErrQuota         = fmt.Errorf("%w: content pack quota reached", shared.ErrValidation)
	ErrSigningKey    = fmt.Errorf("%w: content signing is not configured", shared.ErrInternal)
	ErrUnknownKind   = fmt.Errorf("%w: unknown content kind", shared.ErrValidation)
	ErrSecretsFound  = fmt.Errorf("%w: the pack contains what look like secrets", shared.ErrValidation)
	ErrLintFailed    = fmt.Errorf("%w: the pack failed lint", shared.ErrValidation)
	ErrInvalidDigest = fmt.Errorf("%w: invalid digest", shared.ErrValidation)
)

// IsKnownKind reports whether the platform lints kind.
func IsKnownKind(kind string) bool {
	switch kind {
	case KindNucleiTemplates, KindSemgrepRules, KindWordlist:
		return true
	}
	return false
}

// IsNamespacedKind reports whether kind is a tenant or vendor kind
// (x-<namespace>/<kind>).
func IsNamespacedKind(kind string) bool {
	return kindPattern.MatchString(kind) && len(kind) > 2 && kind[:2] == "x-"
}

// ValidateKind accepts a known kind or a namespaced one.
func ValidateKind(kind string) error {
	if IsKnownKind(kind) || IsNamespacedKind(kind) {
		return nil
	}
	return fmt.Errorf("%w %q (known: %s, %s, %s; or x-<namespace>/<kind>)", ErrUnknownKind, kind, KindNucleiTemplates, KindSemgrepRules, KindWordlist)
}

// ValidateName checks a pack name: lower case, digits, '.', '_', '-'.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%w: name must be 1-64 of a-z 0-9 . _ - and start with a letter or digit", shared.ErrValidation)
	}
	return nil
}

// ValidateVersion checks a pack version (for example 10.4.9 or 2026-10-08).
func ValidateVersion(v string) error {
	if !versionPattern.MatchString(v) {
		return fmt.Errorf("%w: version must be 1-64 of A-Z a-z 0-9 . _ + - and start with a letter or digit", shared.ErrValidation)
	}
	return nil
}

// ValidateDigest checks a sha256:<hex> digest.
func ValidateDigest(d string) error {
	if !digestPattern.MatchString(d) {
		return ErrInvalidDigest
	}
	return nil
}

// Issue is one lint finding. It never carries a secret's value.
type Issue struct {
	Path    string `json:"path,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MaxIssues bounds each list of a LintReport; Truncated says when more were
// found.
const MaxIssues = 200

// LintReport is the platform's verdict on a pack's content.
type LintReport struct {
	Tier     Tier    `json:"tier"`
	Files    int     `json:"files"`
	Items    int     `json:"items"` // templates, rules or wordlist lines
	Errors   []Issue `json:"errors,omitempty"`
	Warnings []Issue `json:"warnings,omitempty"`
	// Secrets are what look like credentials (kind and path, never the
	// value). They block the pack unless the uploader acknowledged them.
	Secrets             []Issue `json:"secrets,omitempty"`
	SecretsAcknowledged bool    `json:"secrets_acknowledged,omitempty"`
	// Excluded counts the files a platform ingest left out of the pack
	// because they failed lint (each also a warning, up to MaxIssues).
	Excluded  int  `json:"excluded,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
}

func (r *LintReport) add(list *[]Issue, it Issue) {
	if len(*list) >= MaxIssues {
		r.Truncated = true
		return
	}
	*list = append(*list, it)
}

// Error records a lint error (the pack is refused).
func (r *LintReport) Error(path, code, msg string) { r.add(&r.Errors, Issue{path, code, msg}) }

// Warn records a warning.
func (r *LintReport) Warn(path, code, msg string) { r.add(&r.Warnings, Issue{path, code, msg}) }

// Secret records a suspected secret of kind in path.
func (r *LintReport) Secret(path, kind string) {
	r.add(&r.Secrets, Issue{path, "SECRET_" + kind, "looks like a " + kind})
}

// Blob is the stored canonical archive of a digest, in one tenant's
// namespace.
type Blob struct {
	TenantID   shared.ID
	Digest     string
	SizeBytes  int64
	FileCount  int
	StorageKey string
	CreatedAt  time.Time
}

// Pack is a named, versioned, signed pack over one blob.
type Pack struct {
	ID           shared.ID
	TenantID     shared.ID
	Name         string
	Version      string
	Kind         string
	Digest       string
	SizeBytes    int64 // from the blob
	FileCount    int   // from the blob
	Tier         Tier
	Status       Status
	Source       Source
	SourceRef    string
	Lint         LintReport
	Signature    []byte // the DSSE envelope (JSON)
	CreatedBy    *shared.ID
	CreatedAt    time.Time
	RevokedAt    *time.Time
	RevokedBy    *shared.ID
	RevokeReason string
}

// Filter narrows a list of a tenant's packs.
type Filter struct {
	Kind   string
	Name   string
	Status Status
}

// Repository stores packs and blobs. Every method is tenant-scoped; a pack
// or blob of another tenant is ErrNotFound.
type Repository interface {
	GetBlob(ctx context.Context, tenantID shared.ID, digest string) (*Blob, error)
	// CreateBlob stores b unless the tenant already has its digest; created
	// is false then (and b's storage key is unused).
	CreateBlob(ctx context.Context, b *Blob) (created bool, err error)
	// Create stores p; ErrExists when the tenant has its name and version.
	Create(ctx context.Context, p *Pack) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Pack, error)
	List(ctx context.Context, tenantID shared.ID, f Filter, limit, offset int) ([]*Pack, int, error)
	// Revoke revokes an active pack; ErrNotActive when it is revoked.
	Revoke(ctx context.Context, tenantID, id shared.ID, by *shared.ID, reason string, at time.Time) error
	// Usage is the tenant's pack count and stored bytes.
	Usage(ctx context.Context, tenantID shared.ID) (packs int, bytes int64, err error)
}
