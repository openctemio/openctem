// Package supportaccess is the only sanctioned way a platform administrator
// sees an organization's data: the organization's owner grants one named
// administrator time-boxed, read-only access for a reason, and the
// administrator opens support sessions inside that grant from the console.
//
// Design: docs/rfcs/RFC-063-support-access.md.
package supportaccess

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits of a grant.
const (
	MinDuration     = time.Hour
	MaxDuration     = 72 * time.Hour
	DefaultDuration = 4 * time.Hour
	MinReasonLength = 10
	MaxReasonLength = 500
	MaxCaseRefLen   = 64
)

// Scopes: the data areas a grant opens. Read-only at every scope.
const (
	ScopeFindings = "findings"
	ScopeAssets   = "assets"
)

// AllScopes is every scope, the default of a new grant.
var AllScopes = []string{ScopeFindings, ScopeAssets}

// LevelRead is the only access level: support never writes.
const LevelRead = "read"

// Grant is an organization's consent for one administrator.
type Grant struct {
	ID         shared.ID
	TenantID   shared.ID
	AdminID    shared.ID
	AdminEmail string
	AdminName  string
	Level      string
	Scopes     []string
	Reason     string
	CaseRef    string
	GrantedBy  shared.ID
	StartsAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	RevokedBy  *shared.ID
	CreatedAt  time.Time

	// Read-side: support sessions opened under the grant and the last access.
	SessionCount int
	LastAccessAt *time.Time
	OpenSession  bool
}

// ActiveAt reports whether the grant can be used at now: not revoked and
// inside its window.
func (g *Grant) ActiveAt(now time.Time) bool {
	return g != nil && g.RevokedAt == nil && !now.Before(g.StartsAt) && now.Before(g.ExpiresAt)
}

// HasScope reports whether the grant opens scope.
func (g *Grant) HasScope(scope string) bool { return g != nil && slices.Contains(g.Scopes, scope) }

// Session is one support session the administrator opened under a grant,
// bound to the console session that opened it.
type Session struct {
	ID               shared.ID
	TenantID         shared.ID
	GrantID          shared.ID
	AdminID          shared.ID
	ConsoleSessionID shared.ID
	Reason           string
	StartedAt        time.Time
	LastAccessAt     *time.Time
	EndedAt          *time.Time
	EndReason        string
}

// LiveSession is a session resolved for one request: the session, its grant
// and the organization's name. Resolved on every request, never cached.
type LiveSession struct {
	Session    Session
	Grant      Grant
	TenantName string
}

// NormalizeScopes validates and de-duplicates requested scopes; empty means
// every scope.
func NormalizeScopes(in []string) ([]string, error) {
	if len(in) == 0 {
		return slices.Clone(AllScopes), nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if !slices.Contains(AllScopes, s) {
			return nil, fmt.Errorf("%w: unknown scope %q (findings, assets)", shared.ErrValidation, s)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out, nil
}

// NormalizeReason checks a reason (10 to 500 characters, no control characters).
func NormalizeReason(r string) (string, error) {
	r = strings.TrimSpace(r)
	n := utf8.RuneCountInString(r)
	if n < MinReasonLength || n > MaxReasonLength {
		return "", fmt.Errorf("%w: the reason is %d to %d characters", shared.ErrValidation, MinReasonLength, MaxReasonLength)
	}
	for _, c := range r {
		if c < 0x20 && c != '\n' && c != '\t' {
			return "", fmt.Errorf("%w: the reason has a control character", shared.ErrValidation)
		}
	}
	return r, nil
}

// NormalizeCaseRef checks an optional case reference.
func NormalizeCaseRef(c string) (string, error) {
	c = strings.TrimSpace(c)
	if utf8.RuneCountInString(c) > MaxCaseRefLen {
		return "", fmt.Errorf("%w: the case reference is at most %d characters", shared.ErrValidation, MaxCaseRefLen)
	}
	for _, r := range c {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: the case reference has a control character", shared.ErrValidation)
		}
	}
	return c, nil
}

// Repository stores grants and sessions. Every grant query carries the
// tenant, or is keyed on the administrator for the console's own list.
type Repository interface {
	CreateGrant(ctx context.Context, g *Grant) error
	// GetGrant returns ErrGrantNotFound unless the grant belongs to tenantID.
	GetGrant(ctx context.Context, tenantID, id shared.ID) (*Grant, error)
	// ListGrants returns the organization's grants, newest first (at most limit).
	ListGrants(ctx context.Context, tenantID shared.ID, limit int) ([]*Grant, error)
	// ListActiveGrants returns the organization's grants usable at now.
	ListActiveGrants(ctx context.Context, tenantID shared.ID, now time.Time) ([]*Grant, error)
	// RevokeGrant marks a live grant revoked and ends its open sessions in one
	// transaction; ErrGrantNotFound when it is not the tenant's or already
	// revoked or expired.
	RevokeGrant(ctx context.Context, tenantID, id, by shared.ID, now time.Time) (*Grant, error)

	// ListGrantsForAdmin returns the grants naming adminID that are usable at now.
	ListGrantsForAdmin(ctx context.Context, adminID shared.ID, now time.Time) ([]*Grant, error)
	// GetGrantForAdmin returns the grant only when it names adminID and is
	// usable at now; ErrGrantNotFound otherwise.
	GetGrantForAdmin(ctx context.Context, adminID, id shared.ID, now time.Time) (*Grant, error)

	CreateSession(ctx context.Context, s *Session) error
	// LiveSession resolves a session for one request: it must be open, opened
	// by adminID in consoleSessionID, and its grant usable at now. Anything
	// else is ErrNoLiveSession. It records the access time.
	LiveSession(ctx context.Context, id, adminID, consoleSessionID shared.ID, now time.Time) (*LiveSession, error)
	// EndSessionForPlatform ends an open session of adminID (a platform
	// principal: keyed on the administrator, the tenant comes back).
	EndSessionForPlatform(ctx context.Context, id, adminID shared.ID, reason string, now time.Time) (*Session, error)
}

// Errors.
var (
	ErrGrantNotFound      = fmt.Errorf("%w: support grant not found", shared.ErrNotFound)
	ErrNoLiveSession      = fmt.Errorf("%w: no active support grant for this access", shared.ErrForbidden)
	ErrGrantRequired      = fmt.Errorf("%w: no active support grant names you for this organization", shared.ErrForbidden)
	ErrNotSupportAdmin    = fmt.Errorf("%w: no platform support administrator has this email", shared.ErrValidation)
	ErrScopeNotGranted    = fmt.Errorf("%w: the grant does not include this data", shared.ErrForbidden)
	ErrAuditUnavailable   = fmt.Errorf("support access could not be audited")
	ErrInvalidDuration    = fmt.Errorf("%w: duration is 1 to 72 hours", shared.ErrValidation)
	ErrTooManyActiveGrant = fmt.Errorf("%w: this administrator already holds an active grant here; revoke it first", shared.ErrConflict)
)

// ---------------------------------------------------------------------------
// The read model support sees: explicit allow-listed fields only. No evidence,
// code snippets, secret values, descriptions, comments, attachments or
// people's emails are ever selected.
// ---------------------------------------------------------------------------

// Overview is the organization at a glance.
type Overview struct {
	TenantName             string           `json:"tenant_name"`
	AssetCount             int64            `json:"asset_count"`
	OpenFindingCount       int64            `json:"open_finding_count"`
	OpenFindingsBySeverity map[string]int64 `json:"open_findings_by_severity"`
}

// FindingView is one finding as support sees it.
type FindingView struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	Source          string     `json:"source"`
	ToolName        string     `json:"tool_name"`
	RuleID          string     `json:"rule_id"`
	CVEID           string     `json:"cve_id,omitempty"`
	CWEIDs          []string   `json:"cwe_ids"`
	AssetID         string     `json:"asset_id,omitempty"`
	AssetName       string     `json:"asset_name,omitempty"`
	AssetType       string     `json:"asset_type,omitempty"`
	FilePath        string     `json:"file_path,omitempty"`
	StartLine       int        `json:"start_line,omitempty"`
	SLAStatus       string     `json:"sla_status,omitempty"`
	FirstDetectedAt *time.Time `json:"first_detected_at,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
}

// AssetView is one asset as support sees it.
type AssetView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Type         string     `json:"type"`
	Criticality  string     `json:"criticality"`
	Status       string     `json:"status"`
	Exposure     string     `json:"exposure"`
	RiskScore    int        `json:"risk_score"`
	FindingCount int64      `json:"finding_count"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
}

// ListQuery pages and filters a support list.
type ListQuery struct {
	Search   string
	Severity string // findings only
	Status   string
	Limit    int
	Offset   int
}

// ReadRepository is support's read model. Every query is scoped to tenantID
// (from the live grant, never the request) and leaves out the assets of
// private programs (and their findings), which only program members and
// owners see.
type ReadRepository interface {
	Overview(ctx context.Context, tenantID shared.ID) (*Overview, error)
	ListFindings(ctx context.Context, tenantID shared.ID, q ListQuery) ([]FindingView, int64, error)
	GetFinding(ctx context.Context, tenantID, id shared.ID) (*FindingView, error)
	ListAssets(ctx context.Context, tenantID shared.ID, q ListQuery) ([]AssetView, int64, error)
	GetAsset(ctx context.Context, tenantID, id shared.ID) (*AssetView, error)
}

// ErrNotFound: not in this organization (or hidden from support).
var ErrNotFound = fmt.Errorf("%w: not found", shared.ErrNotFound)
