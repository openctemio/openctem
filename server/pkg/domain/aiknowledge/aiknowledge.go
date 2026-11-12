// Package aiknowledge holds the knowledge an organization gives its AI agents:
// sources, document versions and their chunks, and what a run retrieved.
// Design: docs/architecture/ai-knowledge.md.
package aiknowledge

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors.
var (
	ErrSourceNotFound   = fmt.Errorf("%w: knowledge source not found", shared.ErrNotFound)
	ErrDocumentNotFound = fmt.Errorf("%w: knowledge document not found", shared.ErrNotFound)
	ErrNameTaken        = fmt.Errorf("%w: a knowledge source with this name exists", shared.ErrConflict)
	ErrNotPending       = fmt.Errorf("%w: nothing is waiting for approval", shared.ErrConflict)
	ErrStateChanged     = fmt.Errorf("%w: the knowledge source changed", shared.ErrConflict)
)

// Origin is where a source's documents come from.
type Origin string

// Origins.
const (
	OriginUpload Origin = "upload"
)

// Visibility decides which AI agents may retrieve a source.
type Visibility string

// Visibilities.
const (
	// VisibilityOrganization: every AI agent of the organization.
	VisibilityOrganization Visibility = "organization"
	// VisibilityTeams: AI agents that are members of one of the source's teams.
	VisibilityTeams Visibility = "teams"
)

// Valid reports a known visibility.
func (v Visibility) Valid() bool { return v == VisibilityOrganization || v == VisibilityTeams }

// Class is a source's data class (the AI egress classes that knowledge may
// carry: internal, or restricted, which is masked strictly).
type Class string

// Classes.
const (
	ClassInternal   Class = "internal"
	ClassRestricted Class = "restricted"
)

// Valid reports a known class.
func (c Class) Valid() bool { return c == ClassInternal || c == ClassRestricted }

// SourceStatus is a source's approval state.
type SourceStatus string

// Source statuses.
const (
	SourcePending  SourceStatus = "pending"
	SourceApproved SourceStatus = "approved"
	SourceRejected SourceStatus = "rejected"
	SourceDisabled SourceStatus = "disabled"
)

// DocumentStatus is a document version's approval state.
type DocumentStatus string

// Document statuses.
const (
	DocumentPending    DocumentStatus = "pending"
	DocumentApproved   DocumentStatus = "approved"
	DocumentRejected   DocumentStatus = "rejected"
	DocumentSuperseded DocumentStatus = "superseded"
)

// QuarantinePromptInjection: ingest found text that tries to instruct a model.
const QuarantinePromptInjection = "prompt_injection"

// Source is a named container of documents.
type Source struct {
	ID             shared.ID
	TenantID       shared.ID
	Name           string
	Description    string
	Origin         Origin
	Visibility     Visibility
	Class          Class
	Status         SourceStatus
	TeamIDs        []shared.ID
	CreatedBy      *shared.ID
	DecidedBy      *shared.ID
	DecidedAt      *time.Time
	SelfApproved   bool
	RejectedReason string
	CreatedAt      time.Time
	UpdatedAt      time.Time

	// Counts (list and detail reads).
	Documents        int
	PendingDocuments int
	Bytes            int64
}

// Document is one version of one document.
type Document struct {
	ID               shared.ID
	TenantID         shared.ID
	SourceID         shared.ID
	LineageID        shared.ID
	Version          int
	Title            string
	Status           DocumentStatus
	Quarantined      bool
	QuarantineReason string
	ContentSHA256    string
	Bytes            int
	Chunks           int
	CreatedBy        *shared.ID
	DecidedBy        *shared.ID
	DecidedAt        *time.Time
	CreatedAt        time.Time
}

// Chunk is a section of a document version.
type Chunk struct {
	Ordinal int
	Title   string
	Body    string
}

// NewDocument is a document version with its chunks, stored in one
// transaction.
type NewDocument struct {
	Document *Document
	Chunks   []Chunk
}

// Usage is what an organization stores.
type Usage struct {
	Sources   int
	Documents int
	Bytes     int64
}

// Retriever is the AI principal a search runs as. The tenant and the agent
// come from the run (or the previewing caller's choice of agent, checked by
// the service), never from a search argument.
type Retriever struct {
	TenantID shared.ID
	// AgentID is the AI agent's user id: team visibility is its own team
	// membership.
	AIAgentID shared.ID
	// MaxClass is the highest class the agent may receive.
	MaxClass Class
}

// Hit is one retrieved chunk.
type Hit struct {
	ChunkID       shared.ID
	DocumentID    shared.ID
	SourceID      shared.ID
	SourceName    string
	Visibility    Visibility
	Class         Class
	DocumentTitle string
	ChunkTitle    string
	Body          string
	VersionDigest string
	UpdatedAt     time.Time
	Score         float64
}

// RetrievalMode is how a run retrieved knowledge.
type RetrievalMode string

// Retrieval modes.
const (
	ModeNone    RetrievalMode = "none"
	ModeLexical RetrievalMode = "lexical"
)

// LexicalIndex names the lexical index version recorded on a run.
const LexicalIndex = "fts-simple-trgm.1"

// RunExcerpt is one excerpt a run saw.
type RunExcerpt struct {
	Ordinal       int
	ChunkID       shared.ID
	DocumentID    shared.ID
	SourceID      shared.ID
	VersionDigest string
	Score         float64
	Cited         bool
}

// Citation is a stored excerpt as a viewer may see it.
type Citation struct {
	Ordinal       int
	DocumentID    *shared.ID
	SourceID      *shared.ID
	SourceName    string
	DocumentTitle string
	ChunkTitle    string
	VersionDigest string
	Score         float64
	Cited         bool
	// Restricted: the viewer may not see the source, so names are withheld.
	Restricted bool
	// Deleted: the document was deleted since the run.
	Deleted bool
}

// Repository stores knowledge. Every method is tenant-scoped.
type Repository interface {
	CreateSource(ctx context.Context, s *Source) error
	GetSource(ctx context.Context, tenantID, id shared.ID) (*Source, error)
	ListSources(ctx context.Context, tenantID shared.ID) ([]*Source, error)
	UpdateSourceText(ctx context.Context, tenantID, id shared.ID, name, description string) error
	DeleteSource(ctx context.Context, tenantID, id shared.ID) error
	// Decide moves a source from one of from to status, recording the decision.
	// On approval, every pending document version becomes approved and the
	// approved version it replaces superseded, in one transaction; quarantined
	// pending versions are approved only when ackQuarantine is true (else
	// ErrNotPending when that leaves nothing to approve on an approved source).
	Decide(ctx context.Context, tenantID, id shared.ID, from []SourceStatus, to SourceStatus, by shared.ID,
		selfApproved bool, reason string, ackQuarantine bool) error
	// RejectPending rejects the pending versions of a source that stays as it
	// is (an approved source keeps serving its approved versions).
	RejectPending(ctx context.Context, tenantID, id, by shared.ID) error
	Usage(ctx context.Context, tenantID shared.ID) (Usage, error)

	// AddDocument stores a pending version with its chunks; a nil LineageID
	// starts a new document, otherwise the version follows the lineage's
	// latest.
	AddDocument(ctx context.Context, in NewDocument) error
	ListDocuments(ctx context.Context, tenantID, sourceID shared.ID) ([]*Document, error)
	GetDocument(ctx context.Context, tenantID, id shared.ID) (*Document, error)
	// DeleteDocument removes every version of the document's lineage.
	DeleteDocument(ctx context.Context, tenantID, id shared.ID) error

	// Search returns the best approved chunks the retriever may see.
	Search(ctx context.Context, r Retriever, query string, limit int) ([]Hit, error)
	// RecordRun stores the run's retrieval mode and excerpts.
	RecordRun(ctx context.Context, tenantID, runID shared.ID, mode RetrievalMode, index string, ex []RunExcerpt) error
	// Citations lists a run's excerpts; viewerAll: the viewer sees every
	// source, else a team source is named only to a member of one of its
	// teams.
	Citations(ctx context.Context, tenantID, runID, viewer shared.ID, viewerAll bool) ([]Citation, RetrievalMode, error)
}
