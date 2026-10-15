// Package ticketlink is the link between an OpenCTEM object (a finding or a
// remediation task) and a tracker issue, with the integration that owns the
// issue (research 157). Links are created by the platform (create ticket) or
// a person (link an existing issue), never from a report.
package ticketlink

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Roles of a link.
const (
	RoleOwn     = "own"     // the object's own issue
	RoleSubtask = "subtask" // a finding's issue under its task's issue
	RoleEpic    = "epic"    // a campaign's epic
)

// States of a link.
const (
	StateActive   = "active"
	StateDeleted  = "deleted"  // the issue was deleted in the tracker
	StateUnlinked = "unlinked" // a person removed the link
)

// Sources of a link.
const (
	SourcePlatform  = "platform"
	SourcePerson    = "person"
	SourceMigration = "migration"
)

// Link is one object ↔ issue link.
type Link struct {
	ID            shared.ID
	TenantID      shared.ID
	IntegrationID shared.ID
	Provider      string
	FindingID     *shared.ID
	CampaignID    *shared.ID
	ExternalID    string
	ExternalKey   string
	ProjectKey    string
	URL           string
	Role          string
	State         string
	Source        string
	CreatedBy     *shared.ID
	LastStatus    string
	LastSyncedAt  *time.Time
	SyncError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

var issueKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*-[0-9]+$`)

// ValidKey reports whether k is a tracker issue key (PROJECT-123).
func ValidKey(k string) bool { return len(k) <= 64 && issueKeyRe.MatchString(k) }

// ProjectOf returns the project key of an issue key.
func ProjectOf(key string) string {
	if i := strings.LastIndex(key, "-"); i > 0 {
		return key[:i]
	}
	return ""
}

// BrowseURL builds the issue's browse URL on a site (no trailing slash).
func BrowseURL(site, key string) string { return strings.TrimRight(site, "/") + "/browse/" + key }

// KeyFromURL parses an issue key from a browse URL on the given site. The
// host (and scheme) must equal the site's: a URL on another host never names
// an issue of this integration.
func KeyFromURL(site, raw string) (string, error) {
	su, err := url.Parse(strings.TrimSpace(site))
	if err != nil || su.Host == "" {
		return "", fmt.Errorf("%w: the integration has no site URL", shared.ErrValidation)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, su.Scheme) || !strings.EqualFold(u.Host, su.Host) {
		return "", fmt.Errorf("%w: the URL is not on the integration's site", shared.ErrValidation)
	}
	prefix := strings.TrimRight(su.Path, "/") + "/browse/"
	if !strings.HasPrefix(u.Path, prefix) {
		return "", fmt.Errorf("%w: not an issue URL", shared.ErrValidation)
	}
	key := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(u.Path, prefix), "/"))
	if !ValidKey(key) {
		return "", fmt.Errorf("%w: not an issue URL", shared.ErrValidation)
	}
	return key, nil
}

// New builds a link of a finding or a campaign (exactly one). site is the
// integration's base URL: the link's URL must be https on that same host.
func New(tenantID, integrationID shared.ID, findingID, campaignID *shared.ID, key, externalID, site, browseURL, role, source string, by *shared.ID) (*Link, error) {
	if (findingID == nil) == (campaignID == nil) {
		return nil, fmt.Errorf("%w: a link names a finding or a task", shared.ErrValidation)
	}
	key = strings.ToUpper(strings.TrimSpace(key))
	if !ValidKey(key) {
		return nil, fmt.Errorf("%w: invalid issue key", shared.ErrValidation)
	}
	if browseURL == "" || len(browseURL) > 2048 || len(externalID) > 64 {
		return nil, fmt.Errorf("%w: invalid issue URL", shared.ErrValidation)
	}
	su, err := url.Parse(strings.TrimSpace(site))
	if err != nil || su.Host == "" {
		return nil, fmt.Errorf("%w: the integration has no site URL", shared.ErrValidation)
	}
	bu, err := url.Parse(browseURL)
	if err != nil || bu.Scheme != "https" || !strings.EqualFold(bu.Host, su.Host) || bu.User != nil {
		return nil, fmt.Errorf("%w: the issue URL must be https on the integration's site", shared.ErrValidation)
	}
	switch role {
	case RoleOwn, RoleSubtask, RoleEpic:
	default:
		return nil, fmt.Errorf("%w: invalid link role", shared.ErrValidation)
	}
	switch source {
	case SourcePlatform, SourcePerson:
	default:
		return nil, fmt.Errorf("%w: invalid link source", shared.ErrValidation)
	}
	now := time.Now().UTC()
	return &Link{
		ID: shared.NewID(), TenantID: tenantID, IntegrationID: integrationID, Provider: "jira",
		FindingID: findingID, CampaignID: campaignID, ExternalID: externalID, ExternalKey: key,
		ProjectKey: ProjectOf(key), URL: browseURL, Role: role, State: StateActive, Source: source,
		CreatedBy: by, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// MaxLinksPerIssue bounds how many objects one issue moves at once.
const MaxLinksPerIssue = 500

// ErrAlreadyLinked: the object already has an active link to the issue.
var ErrAlreadyLinked = fmt.Errorf("%w: the issue is already linked", shared.ErrConflict)

// ErrNotFound: no such link for the tenant.
var ErrNotFound = fmt.Errorf("%w: ticket link not found", shared.ErrNotFound)

// Repository stores links. Every method is tenant-scoped.
type Repository interface {
	Create(ctx context.Context, l *Link) error
	Get(ctx context.Context, tenantID, id shared.ID) (*Link, error)
	ListForFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*Link, error)
	ListForCampaign(ctx context.Context, tenantID, campaignID shared.ID) ([]*Link, error)
	// FindByIssue lists the active links of an issue of an integration (at
	// most MaxLinksPerIssue).
	FindByIssue(ctx context.Context, tenantID, integrationID shared.ID, key string) ([]*Link, error)
	// SetState moves a link to unlinked or deleted.
	SetState(ctx context.Context, tenantID, id shared.ID, state string) error
	// RecordSync stores the last status pushed or read and the last error.
	RecordSync(ctx context.Context, tenantID, id shared.ID, status, syncErr string, at time.Time) error
}
