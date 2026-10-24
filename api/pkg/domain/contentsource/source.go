// Package contentsource is the domain of rule sources: where the platform
// fetches rules, templates and wordlists from, and the immutable snapshots a
// sync produces. The platform is the only fetcher; sensors and CI receive
// snapshots by digest. Design: docs/architecture/content-sources.md.
package contentsource

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope is who owns a source.
type Scope string

// Scopes. A platform source has no tenant and is managed by platform
// administrators only; a tenant source belongs to one organization.
const (
	ScopePlatform Scope = "platform"
	ScopeTenant   Scope = "tenant"
)

// Kind is the content a source holds (the content pack kind).
type Kind string

// Kinds the platform syncs today.
const (
	KindSemgrepRules    Kind = "semgrep-rules"
	KindNucleiTemplates Kind = "nuclei-templates"
	KindWordlist        Kind = "wordlist"
)

// IsValid reports whether k can be synced.
func (k Kind) IsValid() bool {
	switch k {
	case KindSemgrepRules, KindNucleiTemplates, KindWordlist:
		return true
	}
	return false
}

// Origin is how a source is fetched.
type Origin string

// Origins. Only git is accepted today; https-archive, upload and hub (a
// package of the content hub, whose rule namespace is the publisher's) are
// reserved in the schema.
const (
	OriginGit Origin = "git"
)

// PromotionPolicy decides what happens to a new candidate snapshot.
type PromotionPolicy string

// Policies. auto promotes a candidate whose checks all pass; review always
// waits for a second member.
const (
	PolicyAuto   PromotionPolicy = "auto"
	PolicyReview PromotionPolicy = "review"
)

// IsValid reports whether p is a known policy.
func (p PromotionPolicy) IsValid() bool { return p == PolicyAuto || p == PolicyReview }

// Availability is how a platform source is offered to organizations.
type Availability string

// Availabilities.
const (
	AvailabilityDefaultOn Availability = "default_on"
	AvailabilityOptIn     Availability = "opt_in"
	AvailabilityHidden    Availability = "hidden"
)

// IsValid reports whether a is a known availability.
func (a Availability) IsValid() bool {
	switch a {
	case AvailabilityDefaultOn, AvailabilityOptIn, AvailabilityHidden:
		return true
	}
	return false
}

// SyncStatus is the outcome of the last sync.
type SyncStatus string

// Sync statuses.
const (
	SyncPending SyncStatus = "pending"
	SyncRunning SyncStatus = "running"
	SyncSuccess SyncStatus = "success"
	SyncFailed  SyncStatus = "failed"
)

// Storage modes. mirror keeps the bytes of every retained snapshot; proxy
// fetches and caches them; tenant_hosted leaves the bytes in the tenant's
// network and keeps only the signed pin record. Only mirror is accepted
// today.
const (
	StorageModeMirror       = "mirror"
	StorageModeProxy        = "proxy"
	StorageModeTenantHosted = "tenant_hosted"
)

// PlatformFetched reports whether the platform fetches and holds the
// source's content (mirror or proxy): only such a source counts against the
// content_sources and storage limits.
func (s *Source) PlatformFetched() bool { return s.StorageMode != StorageModeTenantHosted }

// Limits.
const (
	// MinSyncIntervalMinutes is the instance's safety floor for a schedule
	// (0 turns it off); the limit content_sync_floor_minutes can raise it.
	MinSyncIntervalMinutes = 5
	// MaxSyncIntervalMinutes is one week.
	MaxSyncIntervalMinutes = 10080
	// DefaultSyncIntervalMinutes is hourly.
	DefaultSyncIntervalMinutes = 60
	maxNameLen                 = 255
	maxDescriptionLen          = 2000
	maxRefLen                  = 255
	maxURLLen                  = 2048
	maxRepoPathLen             = 512
	maxCAPEMLen                = 65536
	maxUsernameLen             = 255
	minTokenLen                = 8
	maxTokenLen                = 4096
	maxSPDXLen                 = 100
)

// ErrTooManyRequests is the base of rate-limit errors (HTTP 429).
var ErrTooManyRequests = errors.New("too many requests")

// Errors.
var (
	ErrNotFound          = fmt.Errorf("%w: rule source not found", shared.ErrNotFound)
	ErrSnapshotNotFound  = fmt.Errorf("%w: snapshot not found", shared.ErrNotFound)
	ErrSlugTaken         = shared.NewDomainError("SLUG_TAKEN", "a rule source with this slug exists", shared.ErrAlreadyExists)
	ErrNotCandidate      = shared.NewDomainError("NOT_CANDIDATE", "only a candidate snapshot can be promoted or rejected", shared.ErrConflict)
	ErrNoPrevious        = shared.NewDomainError("NO_PREVIOUS", "the source has no previous snapshot to roll back to", shared.ErrConflict)
	ErrFourEyes          = shared.NewDomainError("FOUR_EYES", "this snapshot needs review by a member who did not change the source configuration it came from", shared.ErrForbidden)
	ErrLeaseLost         = shared.NewDomainError("LEASE_LOST", "the sync's claim expired or was taken over", shared.ErrConflict)
	ErrSyncInProgress    = shared.NewDomainError("SYNC_IN_PROGRESS", "the source is being synced", shared.ErrConflict)
	ErrUsernameRequired  = shared.NewDomainError("VALIDATION", "a deploy token needs its own username (shown when the token was created)", shared.ErrValidation)
	ErrPlatformReadOnly  = shared.NewDomainError("FORBIDDEN", "platform rule sources are managed by the platform administrators", shared.ErrForbidden)
	ErrDisabled          = shared.NewDomainError("SOURCE_DISABLED", "the source is disabled", shared.ErrConflict)
	ErrRateLimited       = shared.NewDomainError("RATE_LIMITED", "too many requests for this source; try again later", ErrTooManyRequests)
	ErrUnsupportedOrigin = shared.NewDomainError("VALIDATION", "only git sources are supported", shared.ErrValidation)
)

func validation(msg string) error {
	return shared.NewDomainError("VALIDATION", msg, shared.ErrValidation)
}

var (
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)
	spdxPattern = regexp.MustCompile(`^[A-Za-z0-9.+:()-]+( (AND|OR|WITH) [A-Za-z0-9.+:()-]+)*$`)
	hexSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// MaxRuleIDLen bounds a rule id inside a source, so the full rule key
// (namespace, ':' and id) fits a finding's rule id.
const MaxRuleIDLen = 160

// ValidateSlug checks an organization source's slug, its rule namespace:
// 2-40 of a-z, 0-9 and '-', starting and ending with a letter or digit. '@',
// '/' and ':' never appear in it: platform sources are namespaced "@<slug>"
// and other namespaces (a publisher's "<publisher>/<package>") use '/', so
// none can collide with an organization's slug.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return validation("slug must be 2-40 of a-z 0-9 - and start and end with a letter or digit")
	}
	return nil
}

// ValidateRef checks a git ref to track: a branch or tag name, or a full
// commit SHA.
func ValidateRef(ref string) error {
	if ref == "" || len(ref) > maxRefLen {
		return validation("ref is required (a branch, a tag or a commit SHA)")
	}
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") ||
		strings.ContainsAny(ref, " \t\n\r\x00\\:~^?*[") || strings.Contains(ref, "..") ||
		strings.Contains(ref, "@{") || strings.HasSuffix(ref, ".lock") {
		return validation("ref is not a valid branch, tag or commit SHA")
	}
	return nil
}

// IsUpstreamRevision reports whether ref pins a commit.
func IsUpstreamRevision(ref string) bool { return hexSHA.MatchString(ref) }

// ValidateGitURL checks a repository URL: https only, with a host, without
// user info, query or fragment. It returns the canonical host (lower case,
// with a non-default port), which a stored credential is bound to. Where the
// host resolves to is checked at connect time by the SSRF guard.
func ValidateGitURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURLLen {
		return "", validation("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", validation("url is invalid")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", validation("url must use https")
	}
	if u.User != nil {
		return "", validation("url must not contain user info; set the credential on the source")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", validation("url must not contain a query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasPrefix(host, "-") {
		return "", validation("url must name a host")
	}
	if p := u.Port(); p != "" && p != "443" {
		return net.JoinHostPort(host, p), nil
	}
	return host, nil
}

// CleanRepoPath normalizes a sub-directory of the repository ("" for the
// root). It refuses absolute paths, '..', backslashes and NUL bytes.
func CleanRepoPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" || p == "." {
		return "", nil
	}
	if len(p) > maxRepoPathLen {
		return "", validation("path is too long")
	}
	if strings.ContainsAny(p, "\\\x00") {
		return "", validation("path must use forward slashes")
	}
	parts := strings.Split(p, "/")
	clean := parts[:0]
	for _, seg := range parts {
		switch seg {
		case "..":
			return "", validation("path must not contain '..'")
		case "", ".":
			continue
		}
		clean = append(clean, seg)
	}
	return strings.Join(clean, "/"), nil
}

// ValidateCAPEM checks an optional CA bundle: PEM, CERTIFICATE blocks only,
// each a parseable X.509 certificate, at least one. Public data.
func ValidateCAPEM(caPEM string) error {
	if caPEM == "" {
		return nil
	}
	if len(caPEM) > maxCAPEMLen {
		return validation("CA certificate is too large")
	}
	rest := []byte(caPEM)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return validation("CA certificate must contain only CERTIFICATE blocks")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return validation("CA certificate is not a valid X.509 certificate")
		}
		n++
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		return validation("CA certificate must be PEM encoded")
	}
	return nil
}

// ValidateToken checks a fetch token's shape.
func ValidateToken(token string) error {
	if len(token) < minTokenLen || len(token) > maxTokenLen {
		return validation(fmt.Sprintf("token must be %d-%d characters", minTokenLen, maxTokenLen))
	}
	for _, r := range token {
		if r <= ' ' || r == 0x7f {
			return validation("token must not contain spaces or control characters")
		}
	}
	return nil
}

// ResolveUsername is the git username sent with token. An explicit username
// wins. Otherwise it follows the token type: a GitLab deploy token needs the
// username it was created with, other GitLab tokens use "oauth2", GitHub
// tokens use "x-access-token", anything else "oauth2".
func ResolveUsername(username, token string) (string, error) {
	username = strings.TrimSpace(username)
	if username != "" {
		if len(username) > maxUsernameLen || strings.ContainsAny(username, ":\r\n\x00") {
			return "", validation("username is invalid")
		}
		return username, nil
	}
	switch {
	case strings.HasPrefix(token, "gldt-"):
		return "", ErrUsernameRequired
	case strings.HasPrefix(token, "gl"):
		return "oauth2", nil
	case strings.HasPrefix(token, "ghp_"), strings.HasPrefix(token, "gho_"), strings.HasPrefix(token, "ghu_"),
		strings.HasPrefix(token, "ghs_"), strings.HasPrefix(token, "ghr_"), strings.HasPrefix(token, "github_pat_"):
		return "x-access-token", nil
	}
	return "oauth2", nil
}

// TokenHint is the last four characters of a token, the only part ever shown.
func TokenHint(token string) string {
	if len(token) <= 4 {
		return ""
	}
	return token[len(token)-4:]
}

// Source is a rule source.
type Source struct {
	ID       shared.ID
	Scope    Scope
	TenantID *shared.ID // nil for a platform source
	Slug     string
	// RuleNamespace prefixes the source's rule ids; set by the server at
	// create and never changed (finding fingerprints hash the full rule id).
	RuleNamespace string
	Name          string
	Description   string
	Kind          Kind
	Origin        Origin
	URL           string
	Ref           string
	Path          string

	AuthUsername        string
	CredentialEncrypted string // never leaves the service
	CredentialHint      string
	CredentialUpdatedAt *time.Time
	CAPEM               string

	LicenseSPDX       string
	LicenseServiceUse bool
	Policy            PromotionPolicy
	SyncIntervalMin   int
	NextSyncAt        *time.Time
	SyncRequestedAt   *time.Time
	WebhookSecretHash string
	WebhookSecretAt   *time.Time
	StorageMode       string
	Availability      Availability // platform sources only
	Official          bool         // platform sources only
	Enabled           bool

	CurrentSnapshotID  *shared.ID
	PreviousSnapshotID *shared.ID

	LastSyncAt          *time.Time
	LastSyncStatus      SyncStatus
	LastSyncError       string
	LastSyncCommit      string
	LastSyncReport      []byte // JSON lint report of a refused sync
	ConsecutiveFailures int

	ConfigChangedBy *shared.ID
	ConfigChangedAt *time.Time
	// ConfigAuthors are the members who changed what the source fetches
	// since its last synced snapshot (the snapshot records them).
	ConfigAuthors []shared.ID
	// LeaseUntil and ClaimedAt are set on a source claimed by the sync
	// worker (ClaimDueUnscoped): the lease the claim holds and when it was
	// taken. They are never persisted by Update.
	LeaseUntil time.Time
	ClaimedAt  time.Time
	// configTouched: MarkConfigChanged ran since the source was loaded.
	configTouched bool
	CreatedBy     *shared.ID
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// GitConfig is what a git source fetches.
type GitConfig struct {
	URL  string
	Ref  string
	Path string
}

// NewTenantSource creates an organization's git source.
func NewTenantSource(tenantID shared.ID, slug, name string, kind Kind, git GitConfig, createdBy *shared.ID, now time.Time) (*Source, error) {
	if tenantID.IsZero() {
		return nil, validation("tenant is required")
	}
	s := &Source{
		ID: shared.NewID(), Scope: ScopeTenant, TenantID: &tenantID,
		Origin: OriginGit, Policy: PolicyAuto, SyncIntervalMin: DefaultSyncIntervalMinutes,
		StorageMode: StorageModeMirror, Enabled: true, LicenseServiceUse: true,
		LastSyncStatus: SyncPending, CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now,
	}
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}
	if !kind.IsValid() {
		return nil, validation("kind must be semgrep-rules, nuclei-templates or wordlist")
	}
	s.Slug, s.Kind, s.RuleNamespace = slug, kind, slug
	if err := s.Rename(name, ""); err != nil {
		return nil, err
	}
	if _, err := s.SetGit(git); err != nil {
		return nil, err
	}
	s.MarkConfigChanged(createdBy, now)
	s.NextSyncAt = &now
	return s, nil
}

// IsPlatform reports whether s is a platform source.
func (s *Source) IsPlatform() bool { return s.Scope == ScopePlatform }

// Namespace is the prefix of the source's rule ids: the stored
// RuleNamespace; for a row without one, none for an official platform
// source, "@<slug>" for another platform source, "<slug>" for an
// organization's source.
func (s *Source) Namespace() string {
	switch {
	case s.RuleNamespace != "" || (s.IsPlatform() && s.Official):
		return s.RuleNamespace
	case s.IsPlatform():
		return "@" + s.Slug
	}
	return s.Slug
}

// Rename sets the display name and description.
func (s *Source) Rename(name, description string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxNameLen {
		return validation("name must be 1-255 characters")
	}
	if len(description) > maxDescriptionLen {
		return validation("description must be at most 2000 characters")
	}
	s.Name, s.Description = name, description
	return nil
}

// Host is the canonical host the source fetches from.
func (s *Source) Host() string {
	h, err := ValidateGitURL(s.URL)
	if err != nil {
		return ""
	}
	return h
}

// SetGit sets what the source fetches. It returns true when the host
// changed, in which case the stored credential is cleared: a credential is
// only ever sent to the host it was entered for.
func (s *Source) SetGit(c GitConfig) (hostChanged bool, err error) {
	host, err := ValidateGitURL(c.URL)
	if err != nil {
		return false, err
	}
	ref := strings.TrimSpace(c.Ref)
	if err := ValidateRef(ref); err != nil {
		return false, err
	}
	p, err := CleanRepoPath(c.Path)
	if err != nil {
		return false, err
	}
	oldHost := s.Host()
	s.URL, s.Ref, s.Path = strings.TrimSpace(c.URL), ref, p
	if oldHost != "" && oldHost != host && s.CredentialEncrypted != "" {
		s.ClearCredential()
		return true, nil
	}
	return false, nil
}

// SetCAPEM sets the optional CA bundle trusted for this source only.
func (s *Source) SetCAPEM(caPEM string) error {
	caPEM = strings.TrimSpace(caPEM)
	if err := ValidateCAPEM(caPEM); err != nil {
		return err
	}
	s.CAPEM = caPEM
	return nil
}

// SetLicense sets the declared license.
func (s *Source) SetLicense(spdx string, serviceUse bool) error {
	spdx = strings.TrimSpace(spdx)
	if spdx != "" && (len(spdx) > maxSPDXLen || !spdxPattern.MatchString(spdx)) {
		return validation("license must be an SPDX expression")
	}
	s.LicenseSPDX, s.LicenseServiceUse = spdx, serviceUse
	return nil
}

// SetPolicy sets the promotion policy.
func (s *Source) SetPolicy(p PromotionPolicy) error {
	if !p.IsValid() {
		return validation("promotion policy must be auto or review")
	}
	s.Policy = p
	return nil
}

// SetSchedule sets the sync interval (0 turns the schedule off) and moves
// the next scheduled sync accordingly. floor is the shortest interval the
// organization may use (at least MinSyncIntervalMinutes).
func (s *Source) SetSchedule(minutes, floor int, now time.Time) error {
	if floor < MinSyncIntervalMinutes {
		floor = MinSyncIntervalMinutes
	}
	if minutes != 0 && (minutes < floor || minutes > MaxSyncIntervalMinutes) {
		return validation(fmt.Sprintf("sync interval must be 0 (off) or %d-%d minutes", floor, MaxSyncIntervalMinutes))
	}
	s.SyncIntervalMin = minutes
	if minutes == 0 {
		s.NextSyncAt = nil
	} else if s.NextSyncAt == nil || s.NextSyncAt.After(now.Add(time.Duration(minutes)*time.Minute)) {
		next := now.Add(time.Duration(minutes) * time.Minute)
		s.NextSyncAt = &next
	}
	return nil
}

// SetCredential stores an encrypted credential and its hint.
func (s *Source) SetCredential(username, encrypted, hint string, now time.Time) {
	s.AuthUsername, s.CredentialEncrypted, s.CredentialHint = username, encrypted, hint
	s.CredentialUpdatedAt = &now
}

// ClearCredential removes the stored credential.
func (s *Source) ClearCredential() {
	s.AuthUsername, s.CredentialEncrypted, s.CredentialHint = "", "", ""
	s.CredentialUpdatedAt = nil
}

// HasCredential reports whether a credential is stored.
func (s *Source) HasCredential() bool { return s.CredentialEncrypted != "" }

// MarkConfigChanged records who changed what the source fetches (the
// four-eyes reference for review).
func (s *Source) MarkConfigChanged(by *shared.ID, now time.Time) {
	s.ConfigChangedBy = by
	s.ConfigChangedAt = &now
	s.configTouched = true
}

// ConfigTouched reports whether the configuration was changed on this
// value since it was loaded: only then does Update write who changed it,
// so a stale copy never overwrites a newer author.
func (s *Source) ConfigTouched() bool { return s.configTouched }

// NextScheduled returns the next scheduled sync after a sync at now: the
// interval plus a jitter of up to a tenth of it (at most 5 minutes), so
// sources created together do not sync together. jitter is in [0,1).
func (s *Source) NextScheduled(now time.Time, jitter float64) *time.Time {
	if s.SyncIntervalMin == 0 {
		return nil
	}
	interval := time.Duration(s.SyncIntervalMin) * time.Minute
	j := time.Duration(float64(interval/10) * jitter)
	if j > 5*time.Minute {
		j = 5 * time.Minute
	}
	next := now.Add(interval + j)
	return &next
}

// BelongsTo reports whether s is tenantID's own source.
func (s *Source) BelongsTo(tenantID shared.ID) bool {
	return s.TenantID != nil && s.TenantID.Equals(tenantID)
}

// VisibleTo reports whether tenantID may read s: its own source, or a
// platform source that is offered (not hidden).
func (s *Source) VisibleTo(tenantID shared.ID) bool {
	if s.IsPlatform() {
		return s.Availability != AvailabilityHidden
	}
	return s.BelongsTo(tenantID)
}
