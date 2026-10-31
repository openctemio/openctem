// Package aiknowledge manages the knowledge an organization gives its AI
// agents and retrieves it for a run: sources with a visibility and a data
// class, document versions that a second person approves before any AI agent
// can retrieve them, secret refusal and prompt-injection quarantine at
// ingest, lexical retrieval scoped by the AI agent's own principal, and the
// record of what each run saw.
// Design: docs/architecture/ai-knowledge.md.
package aiknowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/aiprompt"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	kdom "github.com/openctemio/openctem/api/pkg/domain/aiknowledge"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Quotas per organization.
const (
	MaxSources   = 50
	MaxDocuments = 2000
	MaxBytes     = 50 * 1024 * 1024
	// MaxTeams bounds the teams of one source.
	MaxTeams = 50
	// RunExcerpts is how many excerpts a single-shot run receives.
	RunExcerpts = 5
)

// Errors with their own API codes.
var (
	ErrQuota          = fmt.Errorf("%w: knowledge quota reached", shared.ErrValidation)
	ErrTooLarge       = fmt.Errorf("%w: document too large", shared.ErrValidation)
	ErrEmptyDocument  = fmt.Errorf("%w: document is empty", shared.ErrValidation)
	ErrHoldsSecret    = fmt.Errorf("%w: document holds a credential", shared.ErrValidation)
	ErrSelfApproval   = fmt.Errorf("%w: a second person must approve this knowledge", shared.ErrForbidden)
	ErrQuarantineAck  = fmt.Errorf("%w: quarantined text needs an explicit acknowledgement", shared.ErrConflict)
	ErrSourceInactive = fmt.Errorf("%w: the knowledge source is rejected or disabled", shared.ErrConflict)
)

// AgentLookup reads an AI agent of the organization.
type AIAgentLookup interface {
	Get(ctx context.Context, tenantID, id shared.ID) (*aidom.AIAgent, error)
}

// Service manages knowledge sources and retrieves knowledge.
type Service struct {
	repo      kdom.Repository
	aiAgents  AIAgentLookup
	audit     *auditapp.AuditService
	sanitizer *aiprompt.Sanitizer
	logger    *logger.Logger
}

// New wires the service. agents may be nil (preview search refused).
func New(repo kdom.Repository, aiAgents AIAgentLookup, audit *auditapp.AuditService, log *logger.Logger) *Service {
	return &Service{repo: repo, aiAgents: aiAgents, audit: audit, sanitizer: aiprompt.NewSanitizer(),
		logger: log.With("service", "ai_knowledge")}
}

func (s *Service) log(ctx context.Context, actx auditapp.AuditContext, action audit.Action, id shared.ID, name, msg string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeAIKnowledge, id.String()).WithResourceName(name).WithMessage(msg)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to log audit event", "action", string(action), "error", err)
	}
}

// Actor is the person making a change.
type Actor struct {
	TenantID shared.ID
	UserID   shared.ID
	// Owner: the organization owner may approve their own content with a
	// recent sign-in (recorded as a self-approval).
	Owner bool
}

func (a Actor) valid() error {
	if a.TenantID.IsZero() || a.UserID.IsZero() {
		return fmt.Errorf("%w: a person must make this change", shared.ErrValidation)
	}
	return nil
}

// CreateSourceInput is a new source.
type CreateSourceInput struct {
	Name        string
	Description string
	Visibility  kdom.Visibility
	Class       kdom.Class
	TeamIDs     []shared.ID
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(kdom.Normalize(name))
	if name == "" || utf8.RuneCountInString(name) > 120 || strings.ContainsRune(name, '\n') {
		return "", fmt.Errorf("%w: name must be 1 to 120 characters on one line", shared.ErrValidation)
	}
	return name, nil
}

func cleanDescription(d string) (string, error) {
	d = kdom.Normalize(d)
	if utf8.RuneCountInString(d) > 1000 {
		return "", fmt.Errorf("%w: description is longer than 1000 characters", shared.ErrValidation)
	}
	return d, nil
}

// CreateSource stores a pending source.
func (s *Service) CreateSource(ctx context.Context, a Actor, in CreateSourceInput, actx auditapp.AuditContext) (*kdom.Source, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	name, err := cleanName(in.Name)
	if err != nil {
		return nil, err
	}
	desc, err := cleanDescription(in.Description)
	if err != nil {
		return nil, err
	}
	if !in.Visibility.Valid() || !in.Class.Valid() {
		return nil, fmt.Errorf("%w: visibility or data class", shared.ErrValidation)
	}
	teams := dedupeIDs(in.TeamIDs)
	switch {
	case in.Visibility == kdom.VisibilityTeams && len(teams) == 0:
		return nil, fmt.Errorf("%w: a team source needs at least one team", shared.ErrValidation)
	case in.Visibility == kdom.VisibilityOrganization && len(teams) > 0:
		return nil, fmt.Errorf("%w: an organization source has no teams", shared.ErrValidation)
	case len(teams) > MaxTeams:
		return nil, fmt.Errorf("%w: at most %d teams", shared.ErrValidation, MaxTeams)
	}
	u, err := s.repo.Usage(ctx, a.TenantID)
	if err != nil {
		return nil, err
	}
	if u.Sources >= MaxSources {
		return nil, ErrQuota
	}
	by := a.UserID
	src := &kdom.Source{ID: shared.NewID(), TenantID: a.TenantID, Name: name, Description: desc, Origin: kdom.OriginUpload,
		Visibility: in.Visibility, Class: in.Class, Status: kdom.SourcePending, TeamIDs: teams, CreatedBy: &by}
	if err := s.repo.CreateSource(ctx, src); err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceCreated, src.ID, src.Name, "Knowledge source created",
		map[string]any{"visibility": string(src.Visibility), "data_class": string(src.Class), "teams": len(teams)})
	return s.repo.GetSource(ctx, a.TenantID, src.ID)
}

func dedupeIDs(in []shared.ID) []shared.ID {
	seen := map[shared.ID]bool{}
	out := make([]shared.ID, 0, len(in))
	for _, id := range in {
		if !id.IsZero() && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// UpdateSource changes a source's name and description. Visibility, class
// and teams are fixed at creation: widening who may retrieve text would
// otherwise skip the approval.
func (s *Service) UpdateSource(ctx context.Context, a Actor, id shared.ID, name, description string, actx auditapp.AuditContext) (*kdom.Source, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	n, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	d, err := cleanDescription(description)
	if err != nil {
		return nil, err
	}
	if err := s.repo.UpdateSourceText(ctx, a.TenantID, id, n, d); err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceUpdated, id, n, "Knowledge source renamed or described", nil)
	return s.repo.GetSource(ctx, a.TenantID, id)
}

// GetSource reads a source with its documents.
func (s *Service) GetSource(ctx context.Context, tenantID, id shared.ID) (*kdom.Source, []*kdom.Document, error) {
	src, err := s.repo.GetSource(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	docs, err := s.repo.ListDocuments(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	return src, docs, nil
}

// ListSources lists the organization's sources.
func (s *Service) ListSources(ctx context.Context, tenantID shared.ID) ([]*kdom.Source, error) {
	return s.repo.ListSources(ctx, tenantID)
}

// AddDocumentInput is a document version. Replaces names any version of an
// existing document of the same source: the new text becomes its next
// version, pending until approved, while the approved version keeps serving.
type AddDocumentInput struct {
	Title    string
	Text     string
	Replaces *shared.ID
}

// SecretError names where a refused document holds a credential.
type SecretError struct {
	Line int
	Kind string
}

func (e *SecretError) Error() string { return ErrHoldsSecret.Error() }

// Unwrap lets errors.Is match ErrHoldsSecret.
func (e *SecretError) Unwrap() error { return ErrHoldsSecret }

// AddDocument ingests a document version: normalize, refuse credentials,
// split, flag prompt injection, store pending.
func (s *Service) AddDocument(ctx context.Context, a Actor, sourceID shared.ID, in AddDocumentInput, actx auditapp.AuditContext) (*kdom.Document, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	if len(in.Text) > kdom.MaxDocumentBytes*2 {
		return nil, ErrTooLarge
	}
	title := strings.TrimSpace(kdom.Normalize(in.Title))
	if title == "" || utf8.RuneCountInString(title) > 200 || strings.ContainsRune(title, '\n') {
		return nil, fmt.Errorf("%w: title must be 1 to 200 characters on one line", shared.ErrValidation)
	}
	text := kdom.Normalize(in.Text)
	if text == "" {
		return nil, ErrEmptyDocument
	}
	if len(text) > kdom.MaxDocumentBytes {
		return nil, ErrTooLarge
	}
	if spans := safetext.FindSecrets(text); len(spans) > 0 {
		return nil, &SecretError{Line: strings.Count(text[:spans[0].Start], "\n") + 1, Kind: spans[0].Kind}
	}
	chunks, ok := kdom.Split(text)
	if !ok {
		return nil, ErrTooLarge
	}
	src, err := s.repo.GetSource(ctx, a.TenantID, sourceID)
	if err != nil {
		return nil, err
	}
	if src.Status == kdom.SourceRejected || src.Status == kdom.SourceDisabled {
		return nil, ErrSourceInactive
	}
	var lineage shared.ID
	if in.Replaces != nil {
		prev, err := s.repo.GetDocument(ctx, a.TenantID, *in.Replaces)
		if err != nil || prev.SourceID != sourceID {
			return nil, kdom.ErrDocumentNotFound
		}
		lineage = prev.LineageID
	}
	u, err := s.repo.Usage(ctx, a.TenantID)
	if err != nil {
		return nil, err
	}
	if (in.Replaces == nil && u.Documents >= MaxDocuments) || u.Bytes+int64(len(text)) > MaxBytes {
		return nil, ErrQuota
	}
	sum := sha256.Sum256([]byte(text))
	by := a.UserID
	doc := &kdom.Document{ID: shared.NewID(), TenantID: a.TenantID, SourceID: sourceID, LineageID: lineage, Title: title,
		ContentSHA256: "sha256:" + hex.EncodeToString(sum[:]), Bytes: len(text), CreatedBy: &by}
	if s.injected(title, chunks) {
		doc.Quarantined, doc.QuarantineReason = true, kdom.QuarantinePromptInjection
	}
	if err := s.repo.AddDocument(ctx, kdom.NewDocument{Document: doc, Chunks: chunks}); err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeDocumentAdded, sourceID, src.Name, "Knowledge document added for approval",
		map[string]any{"document_id": doc.ID.String(), "version": doc.Version, "bytes": doc.Bytes,
			"chunks": doc.Chunks, "quarantined": doc.Quarantined, "content_sha256": doc.ContentSHA256})
	return doc, nil
}

// injected reports text that matches a known prompt-injection pattern (the
// same patterns the prompt builder filters).
func (s *Service) injected(title string, chunks []kdom.Chunk) bool {
	hit := func(v string) bool {
		clean := s.sanitizer.SanitizeForPrompt(v)
		return strings.Contains(clean, aiprompt.FilteredMarker) && !strings.Contains(v, aiprompt.FilteredMarker)
	}
	if hit(title) {
		return true
	}
	for _, c := range chunks {
		if hit(c.Title) || hit(c.Body) {
			return true
		}
	}
	return false
}

// Approve approves a source and its pending document versions. The
// approver must not be the author of the source or of a pending version,
// unless they are the organization owner (recorded as a self-approval).
// Quarantined versions need ackQuarantine.
func (s *Service) Approve(ctx context.Context, a Actor, id shared.ID, ackQuarantine bool, actx auditapp.AuditContext) (*kdom.Source, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	src, docs, err := s.GetSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	self := src.Status == kdom.SourcePending && src.CreatedBy != nil && *src.CreatedBy == a.UserID
	quarantined, pending := 0, 0
	for _, d := range docs {
		if d.Status != kdom.DocumentPending {
			continue
		}
		pending++
		if d.CreatedBy != nil && *d.CreatedBy == a.UserID {
			self = true
		}
		if d.Quarantined {
			quarantined++
		}
	}
	if self && !a.Owner {
		return nil, ErrSelfApproval
	}
	if quarantined > 0 && !ackQuarantine {
		return nil, ErrQuarantineAck
	}
	if src.Status == kdom.SourceApproved && pending == 0 {
		return nil, kdom.ErrNotPending
	}
	from := []kdom.SourceStatus{kdom.SourcePending, kdom.SourceApproved, kdom.SourceDisabled}
	if err := s.repo.Decide(ctx, a.TenantID, id, from, kdom.SourceApproved, a.UserID, self, "", ackQuarantine); err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceApproved, id, src.Name, "Knowledge source approved for AI agents",
		map[string]any{"versions": pending, "quarantined_acknowledged": quarantined, "self_approved": self})
	return s.repo.GetSource(ctx, a.TenantID, id)
}

// Reject rejects a pending source, or the pending versions of an approved
// one (the source keeps serving its approved versions).
func (s *Service) Reject(ctx context.Context, a Actor, id shared.ID, reason string, actx auditapp.AuditContext) (*kdom.Source, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(kdom.Normalize(reason))
	if utf8.RuneCountInString(reason) > 500 {
		return nil, fmt.Errorf("%w: reason is longer than 500 characters", shared.ErrValidation)
	}
	src, err := s.repo.GetSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	to := kdom.SourceRejected
	if src.Status == kdom.SourceApproved {
		if src.PendingDocuments == 0 {
			return nil, kdom.ErrNotPending
		}
		to = kdom.SourceApproved
		err = s.repo.RejectPending(ctx, a.TenantID, id, a.UserID)
	} else {
		err = s.repo.Decide(ctx, a.TenantID, id, []kdom.SourceStatus{kdom.SourcePending}, to, a.UserID, false, reason, false)
	}
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceRejected, id, src.Name, "Knowledge rejected",
		map[string]any{"source_status": string(to)})
	return s.repo.GetSource(ctx, a.TenantID, id)
}

// Disable stops every AI agent from retrieving a source at once (tightening
// needs no second person).
func (s *Service) Disable(ctx context.Context, a Actor, id shared.ID, actx auditapp.AuditContext) (*kdom.Source, error) {
	if err := a.valid(); err != nil {
		return nil, err
	}
	src, err := s.repo.GetSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Decide(ctx, a.TenantID, id, []kdom.SourceStatus{kdom.SourceApproved, kdom.SourcePending},
		kdom.SourceDisabled, a.UserID, false, "", false); err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceDisabled, id, src.Name, "Knowledge source disabled", nil)
	return s.repo.GetSource(ctx, a.TenantID, id)
}

// DeleteSource deletes a source with every document.
func (s *Service) DeleteSource(ctx context.Context, a Actor, id shared.ID, actx auditapp.AuditContext) error {
	if err := a.valid(); err != nil {
		return err
	}
	src, err := s.repo.GetSource(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteSource(ctx, a.TenantID, id); err != nil {
		return err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeSourceDeleted, id, src.Name, "Knowledge source deleted", nil)
	return nil
}

// DeleteDocument deletes every version of a document.
func (s *Service) DeleteDocument(ctx context.Context, a Actor, id shared.ID, actx auditapp.AuditContext) error {
	if err := a.valid(); err != nil {
		return err
	}
	d, err := s.repo.GetDocument(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.DeleteDocument(ctx, a.TenantID, id); err != nil {
		return err
	}
	s.log(ctx, actx, audit.ActionAIKnowledgeDocumentDeleted, d.SourceID, d.Title, "Knowledge document deleted",
		map[string]any{"document_id": d.ID.String()})
	return nil
}

// MaxClassFor maps an AI agent's data class ceiling to the highest
// knowledge class it may receive; false: none (public ceiling, or a class
// that never leaves the organization).
func MaxClassFor(ceiling aidom.DataClass) (kdom.Class, bool) {
	switch ceiling {
	case aidom.DataClassInternal:
		return kdom.ClassInternal, true
	case aidom.DataClassRestricted:
		return kdom.ClassRestricted, true
	}
	return "", false
}

// Retrieve returns what an AI agent may retrieve for a query. The tenant and
// the agent are the run's; nothing in the query can widen them.
func (s *Service) Retrieve(ctx context.Context, tenantID shared.ID, aiAgent *aidom.AIAgent, query string, limit int) ([]kdom.Hit, error) {
	if aiAgent == nil || aiAgent.TenantID != tenantID {
		return nil, fmt.Errorf("%w: AI agent", shared.ErrNotFound)
	}
	maxClass, ok := MaxClassFor(aiAgent.DataClassCeiling)
	if !ok || len(kdom.Terms(query)) == 0 {
		return nil, nil
	}
	return s.repo.Search(ctx, kdom.Retriever{TenantID: tenantID, AIAgentID: aiAgent.ID, MaxClass: maxClass}, query, limit)
}

// Preview shows a person what one of the organization's AI agents would
// retrieve for a query.
func (s *Service) Preview(ctx context.Context, tenantID, aiAgentID shared.ID, query string) ([]kdom.Hit, error) {
	if s.aiAgents == nil {
		return nil, fmt.Errorf("%w: AI agent", shared.ErrNotFound)
	}
	aiAgent, err := s.aiAgents.Get(ctx, tenantID, aiAgentID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, fmt.Errorf("%w: AI agent", shared.ErrNotFound)
		}
		return nil, err
	}
	return s.Retrieve(ctx, tenantID, aiAgent, query, 8)
}

// Record stores what a run retrieved.
func (s *Service) Record(ctx context.Context, tenantID, runID shared.ID, mode kdom.RetrievalMode, ex []kdom.RunExcerpt) error {
	index := ""
	if mode == kdom.ModeLexical {
		index = kdom.LexicalIndex
	}
	return s.repo.RecordRun(ctx, tenantID, runID, mode, index, ex)
}

// Citations lists a run's excerpts as the viewer may see them.
func (s *Service) Citations(ctx context.Context, tenantID, runID, viewer shared.ID, viewerAll bool) ([]kdom.Citation, kdom.RetrievalMode, error) {
	return s.repo.Citations(ctx, tenantID, runID, viewer, viewerAll)
}
