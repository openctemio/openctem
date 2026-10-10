package bountyprogram

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Exclusion is a program exclusion: an out-of-scope item (or the unlisted
// apex of a program wildcard). It stops every program entry of the tenant
// from covering a name; the organization's own entries are unaffected
// (RFC-065 B7).
type Exclusion struct {
	ID         shared.ID
	TenantID   shared.ID
	ProgramID  shared.ID
	TargetType scope.TargetType
	Pattern    string
	Reason     string
	CreatedAt  time.Time
}

// Matches reports whether the exclusion matches a target value (the same
// matcher as scope entries and exclusions).
func (e Exclusion) Matches(value string) bool {
	return scope.MatchesPattern(e.TargetType, e.Pattern, value)
}

// NewGroup is the group created with a program (data scope, RFC-065 §7).
type NewGroup struct {
	ID   shared.ID
	Name string
	Slug string
	// Member joins the group (the importer); nil for none.
	Member *shared.ID
}

// ImportWrite is everything an import writes, in one transaction.
type ImportWrite struct {
	Program    *Program
	Group      NewGroup
	Entries    []*scope.Target
	Exclusions []Exclusion
}

// ScopeWrite is everything a re-import changes, in one transaction: the
// program row (terms, items, rules, attestation), entries to create and to
// delete, and the program's exclusions replaced as a whole.
type ScopeWrite struct {
	Program        *Program
	CreateEntries  []*scope.Target
	DeleteEntryIDs []shared.ID
	Exclusions     []Exclusion
}

// Repository persists programs. Every method is tenant-scoped.
type Repository interface {
	Import(ctx context.Context, w ImportWrite) error
	ReplaceScope(ctx context.Context, w ScopeWrite) error
	// SetStatus updates the program and sets every one of its entries to
	// entryStatus (active or inactive), in one transaction.
	SetStatus(ctx context.Context, p *Program, entryStatus scope.Status) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Program, error)
	// List lists the tenant's programs; with memberOf set, only those whose
	// group has that user as a member.
	List(ctx context.Context, tenantID shared.ID, memberOf *shared.ID) ([]*Program, error)
	// Entries lists a program's scope entries (any status).
	Entries(ctx context.Context, tenantID, programID shared.ID) ([]*scope.Target, error)
	// TenantEntries lists every scope entry of the tenant (any status, any
	// source): an import reports patterns that already exist and where a
	// program exclusion overlaps the organization's own scope.
	TenantEntries(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error)
	// Exclusions lists the program exclusions of one program, or of every
	// program of the tenant when programID is nil.
	Exclusions(ctx context.Context, tenantID shared.ID, programID *shared.ID) ([]Exclusion, error)
	// IsMember reports whether the user is a member of the program's group.
	IsMember(ctx context.Context, tenantID, programID, userID shared.ID) (bool, error)
	// MemberProgramIDs lists the programs whose group has the user.
	MemberProgramIDs(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)
	// SaveSync writes the source settings, sync state and pending terms.
	SaveSync(ctx context.Context, p *Program) error
	// SyncDue lists active programs with a source not synced since
	// olderThan (all tenants: the controller).
	SyncDue(ctx context.Context, olderThan time.Time, limit int) ([]ProgramRef, error)
}

// ProgramRef names one program of one tenant.
type ProgramRef struct {
	TenantID  shared.ID
	ProgramID shared.ID
}
