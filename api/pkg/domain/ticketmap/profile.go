package ticketmap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Version states.
const (
	VersionDraft      = "draft"
	VersionPublished  = "published"
	VersionSuperseded = "superseded"
)

// Profile is the mapping for one destination (integration × project × issue
// type) and one object kind. Its content lives in versions.
type Profile struct {
	ID            shared.ID  `json:"id"`
	TenantID      shared.ID  `json:"tenant_id"`
	IntegrationID shared.ID  `json:"integration_id"`
	ObjectKind    ObjectKind `json:"object_kind"`
	ProjectID     string     `json:"project_id"`
	ProjectKey    string     `json:"project_key"`
	IssueTypeID   string     `json:"issue_type_id"`
	IssueType     string     `json:"issue_type"`
	Name          string     `json:"name"`
	// PublishedVersion is 0 while nothing is published.
	PublishedVersion int `json:"published_version"`
	// DraftVersion is 0 when there is no open draft.
	DraftVersion int `json:"draft_version"`
	// DryRun: the published version renders and logs only.
	DryRun    bool       `json:"dry_run"`
	Drifted   bool       `json:"drifted"`
	CreatedBy *shared.ID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Version is one immutable (once published) version of a profile.
type Version struct {
	ProfileID   shared.ID    `json:"profile_id"`
	TenantID    shared.ID    `json:"tenant_id"`
	Version     int          `json:"version"`
	State       string       `json:"state"`
	Spec        Spec         `json:"spec"`
	Snapshot    *ProjectMeta `json:"snapshot,omitempty"`
	Note        string       `json:"note,omitempty"`
	CreatedBy   *shared.ID   `json:"created_by,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	PublishedBy *shared.ID   `json:"published_by,omitempty"`
	PublishedAt *time.Time   `json:"published_at,omitempty"`
}

// NewProfile validates and builds a profile.
func NewProfile(tenantID, integrationID shared.ID, kind ObjectKind, projectID, projectKey, issueTypeID, issueType, name string, by *shared.ID) (*Profile, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: object_kind must be finding or task", shared.ErrValidation)
	}
	projectID, projectKey = strings.TrimSpace(projectID), strings.ToUpper(strings.TrimSpace(projectKey))
	issueTypeID, issueType = strings.TrimSpace(issueTypeID), strings.TrimSpace(issueType)
	if projectKey == "" || len(projectKey) > 32 || issueTypeID == "" || len(issueTypeID) > 64 || len(projectID) > 64 || len(issueType) > 128 {
		return nil, fmt.Errorf("%w: a project key and an issue type are required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("%s / %s", projectKey, issueType)
	}
	if len([]rune(name)) > 120 {
		return nil, fmt.Errorf("%w: name is at most 120 characters", shared.ErrValidation)
	}
	now := time.Now().UTC()
	return &Profile{
		ID: shared.NewID(), TenantID: tenantID, IntegrationID: integrationID, ObjectKind: kind,
		ProjectID: projectID, ProjectKey: projectKey, IssueTypeID: issueTypeID, IssueType: issueType,
		Name: name, CreatedBy: by, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// ProfileFilter narrows a profile list.
type ProfileFilter struct {
	IntegrationID *shared.ID
	ObjectKind    ObjectKind
	ProjectKey    string
}

// Repository stores profiles and versions. Every method is tenant-scoped.
type Repository interface {
	CreateProfile(ctx context.Context, p *Profile, first *Version) error
	GetProfile(ctx context.Context, tenantID, id shared.ID) (*Profile, error)
	ListProfiles(ctx context.Context, tenantID shared.ID, f ProfileFilter, page pagination.Pagination) (pagination.Result[*Profile], error)
	// FindPublished returns the profile for a destination, or ErrNotFound.
	FindForDestination(ctx context.Context, tenantID, integrationID shared.ID, kind ObjectKind, projectKey, issueTypeID string) (*Profile, error)
	DeleteProfile(ctx context.Context, tenantID, id shared.ID) error
	SetDryRun(ctx context.Context, tenantID, id shared.ID, dryRun bool) error
	SetDrifted(ctx context.Context, tenantID, id shared.ID, drifted bool) error

	GetVersion(ctx context.Context, tenantID, profileID shared.ID, version int) (*Version, error)
	ListVersions(ctx context.Context, tenantID, profileID shared.ID) ([]*Version, error)
	// SaveDraft creates the draft (version = latest + 1) or replaces the open
	// draft's spec. expectedDraft guards concurrent editors (0 = none open).
	SaveDraft(ctx context.Context, tenantID, profileID shared.ID, spec Spec, snapshot *ProjectMeta, note string, by *shared.ID, expectedDraft int) (*Version, error)
	// Publish makes the open draft the published version and supersedes the
	// previous one, atomically.
	Publish(ctx context.Context, tenantID, profileID shared.ID, draft int, by *shared.ID) (*Version, error)
	DiscardDraft(ctx context.Context, tenantID, profileID shared.ID) error
}

// ErrDraftConflict: someone else changed the draft.
var ErrDraftConflict = fmt.Errorf("%w: the draft was changed by someone else; reload it", shared.ErrConflict)
