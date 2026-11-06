package findinglifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Lifecycle schemes and their versions as stored. A scheme is the default
// one (no context) or a context scheme picked by priority; its versions are
// one draft, the published one and the superseded ones.

// VersionState is where a version is in its life.
type VersionState string

const (
	VersionDraft      VersionState = "draft"
	VersionPublished  VersionState = "published"
	VersionSuperseded VersionState = "superseded"
)

// Errors of schemes and versions.
var (
	ErrSchemeNotFound   = fmt.Errorf("%w: lifecycle not found", shared.ErrNotFound)
	ErrVersionNotFound  = fmt.Errorf("%w: lifecycle version not found", shared.ErrNotFound)
	ErrSchemeKeyTaken   = fmt.Errorf("%w: a lifecycle with this key already exists", shared.ErrConflict)
	ErrDefaultExists    = fmt.Errorf("%w: the organization already has a default lifecycle; give this one a context", shared.ErrConflict)
	ErrDraftExists      = fmt.Errorf("%w: the lifecycle already has a draft", shared.ErrConflict)
	ErrNotDraft         = fmt.Errorf("%w: only a draft can be changed", shared.ErrConflict)
	ErrStaleDraft       = fmt.Errorf("%w: the draft changed since it was read; reload it", shared.ErrConflict)
	ErrSchemeLimit      = fmt.Errorf("%w: the organization has reached its lifecycle limit", shared.ErrValidation)
	ErrSchemeArchived   = fmt.Errorf("%w: the lifecycle is archived", shared.ErrValidation)
	ErrSubStatusInUseBy = fmt.Errorf("%w: a published lifecycle uses this sub-status; publish a version without it first", shared.ErrConflict)
)

// Scheme is a lifecycle scheme.
type Scheme struct {
	id                 shared.ID
	tenantID           shared.ID
	kind               ObjectKind
	key                string
	name               string
	description        string
	priority           int
	context            []Condition // nil = the default scheme
	publishedVersionID *shared.ID
	archivedAt         *time.Time
	createdAt          time.Time
	createdBy          *shared.ID
	updatedAt          time.Time
	updatedBy          *shared.ID
}

// SchemeInput is what a person sets on a scheme.
type SchemeInput struct {
	Key         string
	Name        string
	Description string
	Priority    int
	// Context selects the findings a context scheme applies to; empty for
	// the default scheme.
	Context []Condition
}

// NewScheme validates in and returns a new scheme of tenantID.
func NewScheme(tenantID shared.ID, in SchemeInput, actor *shared.ID, now time.Time) (*Scheme, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	key := strings.TrimSpace(in.Key)
	if !keyPattern.MatchString(key) {
		return nil, fmt.Errorf("%w: key must be 2-40 lowercase letters, digits or underscores, starting with a letter", shared.ErrValidation)
	}
	s := &Scheme{
		id: shared.NewID(), tenantID: tenantID, kind: ObjectKindFinding, key: key,
		createdAt: now, createdBy: actor, updatedAt: now, updatedBy: actor,
	}
	if err := s.set(in.Name, in.Description, in.Priority, in.Context); err != nil {
		return nil, err
	}
	return s, nil
}

// SchemeUpdate is what may change on a scheme (not its key).
type SchemeUpdate struct {
	Name        *string
	Description *string
	Priority    *int
	// Context, when set, replaces the selector; an empty list makes the
	// scheme the default one.
	Context *[]Condition
}

// Update applies u.
func (s *Scheme) Update(u SchemeUpdate, actor *shared.ID, now time.Time) error {
	name, desc, prio, ctxConds := s.name, s.description, s.priority, s.context
	if u.Name != nil {
		name = *u.Name
	}
	if u.Description != nil {
		desc = *u.Description
	}
	if u.Priority != nil {
		prio = *u.Priority
	}
	if u.Context != nil {
		ctxConds = *u.Context
	}
	if err := s.set(name, desc, prio, ctxConds); err != nil {
		return err
	}
	s.updatedAt, s.updatedBy = now, actor
	return nil
}

func (s *Scheme) set(name, description string, priority int, ctxConds []Condition) error {
	n, err := plainText("name", name, MaxNameLen, true)
	if err != nil {
		return err
	}
	d, err := plainText("description", description, MaxDescriptionLen, false)
	if err != nil {
		return err
	}
	if priority < 0 || priority > 1000 {
		return fmt.Errorf("%w: priority must be between 0 and 1000", shared.ErrValidation)
	}
	if len(ctxConds) > 0 {
		if _, v := CompileContext(ctxConds); !v.OK() {
			return v.Err()
		}
	} else {
		ctxConds = nil
	}
	s.name, s.description, s.priority, s.context = n, d, priority, ctxConds
	return nil
}

// Archive retires the scheme: it no longer applies to any finding.
func (s *Scheme) Archive(actor *shared.ID, now time.Time) {
	if s.archivedAt == nil {
		s.archivedAt = &now
	}
	s.updatedAt, s.updatedBy = now, actor
}

// SchemeData reconstitutes a stored scheme.
type SchemeData struct {
	ID                 shared.ID
	TenantID           shared.ID
	Kind               ObjectKind
	Key                string
	Name               string
	Description        string
	Priority           int
	Context            []Condition
	PublishedVersionID *shared.ID
	ArchivedAt         *time.Time
	CreatedAt          time.Time
	CreatedBy          *shared.ID
	UpdatedAt          time.Time
	UpdatedBy          *shared.ID
}

// ReconstituteScheme rebuilds a scheme from storage.
func ReconstituteScheme(d SchemeData) *Scheme {
	return &Scheme{
		id: d.ID, tenantID: d.TenantID, kind: d.Kind, key: d.Key, name: d.Name, description: d.Description,
		priority: d.Priority, context: d.Context, publishedVersionID: d.PublishedVersionID, archivedAt: d.ArchivedAt,
		createdAt: d.CreatedAt, createdBy: d.CreatedBy, updatedAt: d.UpdatedAt, updatedBy: d.UpdatedBy,
	}
}

// Accessors.
func (s *Scheme) ID() shared.ID                  { return s.id }
func (s *Scheme) TenantID() shared.ID            { return s.tenantID }
func (s *Scheme) Kind() ObjectKind               { return s.kind }
func (s *Scheme) Key() string                    { return s.key }
func (s *Scheme) Name() string                   { return s.name }
func (s *Scheme) Description() string            { return s.description }
func (s *Scheme) Priority() int                  { return s.priority }
func (s *Scheme) Context() []Condition           { return s.context }
func (s *Scheme) IsDefault() bool                { return len(s.context) == 0 }
func (s *Scheme) PublishedVersionID() *shared.ID { return s.publishedVersionID }
func (s *Scheme) ArchivedAt() *time.Time         { return s.archivedAt }
func (s *Scheme) IsArchived() bool               { return s.archivedAt != nil }
func (s *Scheme) CreatedAt() time.Time           { return s.createdAt }
func (s *Scheme) CreatedBy() *shared.ID          { return s.createdBy }
func (s *Scheme) UpdatedAt() time.Time           { return s.updatedAt }
func (s *Scheme) UpdatedBy() *shared.ID          { return s.updatedBy }

// Version is one version of a scheme.
type Version struct {
	ID          shared.ID
	TenantID    shared.ID
	SchemeID    shared.ID
	Number      int
	State       VersionState
	Spec        Spec
	SpecHash    string
	Note        string
	CreatedAt   time.Time
	CreatedBy   *shared.ID
	PublishedAt *time.Time
	PublishedBy *shared.ID
}

// EncodeSpec returns the stored form of a spec and its hash. The hash is
// what an editor sends back (If-Match) so two people editing one draft never
// overwrite each other silently.
func EncodeSpec(s Spec) ([]byte, string, error) {
	if s.SubStatuses == nil {
		s.SubStatuses = []string{}
	}
	if s.Transitions == nil {
		s.Transitions = []TransitionSpec{}
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, "", fmt.Errorf("encode lifecycle spec: %w", err)
	}
	if len(raw) > MaxSpecBytes {
		return nil, "", fmt.Errorf("%w: the lifecycle spec is larger than %d bytes", shared.ErrValidation, MaxSpecBytes)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

// NewDraft returns version number of scheme as a draft holding spec.
func NewDraft(scheme *Scheme, number int, spec Spec, actor *shared.ID, now time.Time) (*Version, error) {
	_, hash, err := EncodeSpec(spec)
	if err != nil {
		return nil, err
	}
	return &Version{
		ID: shared.NewID(), TenantID: scheme.TenantID(), SchemeID: scheme.ID(), Number: number,
		State: VersionDraft, Spec: spec, SpecHash: hash, CreatedAt: now, CreatedBy: actor,
	}, nil
}

// PublishedScheme is a published scheme with the spec in force, what the
// engine compiles.
type PublishedScheme struct {
	Scheme  *Scheme
	Version *Version
}

// SchemeRepository stores schemes and versions. Every method is
// tenant-scoped.
type SchemeRepository interface {
	CreateScheme(ctx context.Context, s *Scheme) error
	UpdateScheme(ctx context.Context, s *Scheme) error
	GetScheme(ctx context.Context, tenantID, id shared.ID) (*Scheme, error)
	ListSchemes(ctx context.Context, tenantID shared.ID, kind ObjectKind, includeArchived bool) ([]*Scheme, error)
	// CountLive counts the tenant's schemes of kind that are not archived.
	CountLive(ctx context.Context, tenantID shared.ID, kind ObjectKind) (int, error)

	CreateVersion(ctx context.Context, v *Version) error
	// UpdateDraft replaces a draft's spec when its stored hash is
	// expectedHash (ErrStaleDraft otherwise, ErrNotDraft for a published one).
	UpdateDraft(ctx context.Context, v *Version, expectedHash string) error
	GetVersion(ctx context.Context, tenantID, schemeID shared.ID, number int) (*Version, error)
	ListVersions(ctx context.Context, tenantID, schemeID shared.ID) ([]*Version, error)
	// NextVersionNumber is one above the scheme's highest version.
	NextVersionNumber(ctx context.Context, tenantID, schemeID shared.ID) (int, error)
	// Publish makes the draft the scheme's published version (the previous
	// one becomes superseded), in one transaction.
	Publish(ctx context.Context, v *Version, note string, actor *shared.ID, at time.Time) error

	// Published returns the tenant's live schemes of kind with their
	// published version.
	Published(ctx context.Context, tenantID shared.ID, kind ObjectKind) ([]PublishedScheme, error)
	// SubStatusPublished reports whether a live scheme's published version
	// uses the sub-status.
	SubStatusPublished(ctx context.Context, tenantID, subStatusID shared.ID) (bool, error)
}

// Ref is what the engine needs of a catalog entry.
func (s *SubStatus) Ref() SubStatusRef {
	return SubStatusRef{ID: s.id, Key: s.key, Status: s.canonicalStatus, ClosureReason: s.closureReason, Archived: s.IsArchived()}
}
