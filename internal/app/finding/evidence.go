package finding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app/integration"
	attachmentdom "github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// Evidence / remediation-step limits. Kept conservative — this is manual
// operator input on a finding, not bulk ingest.
const (
	maxEvidenceDescriptionLen = 10000
	maxEvidenceTypeLen        = 64
	maxEvidenceURLLen         = 2048
	maxRemediationStepLen     = 2000
	maxRemediationSteps       = 100
	// maxEvidenceNotes bounds the number of manual note-type evidence records a
	// single finding may hold. Mirrors the maxRemediationSteps guard — without
	// it a findings:write user could loop unbounded note uploads on one finding
	// (row/blob growth).
	maxEvidenceNotes = 200
)

// evidenceContextType is the attachment context_type used to link
// finding-evidence records. It intentionally REUSES the same context_type the
// pentest attachment uploader uses ("finding"), so the pentest /attachments
// GET/list gate — which rejects any non-pentest finding — keeps these generic
// evidence records out of the pentest surface. The generic evidence GET below
// is the only read path for them.
const evidenceContextType = "finding"

// evidenceNotePrefix marks an attachment whose content is a structured
// JSON evidence note (as opposed to an uploaded binary file).
const evidenceNotePrefix = "evidence-note-"

// contentTypeJSON is the stored content-type for note-type evidence records.
const contentTypeJSON = "application/json"

// isEvidenceNote reports whether an attachment is a note-type evidence record
// (JSON payload with the evidence-note filename prefix).
func isEvidenceNote(att *attachmentdom.Attachment) bool {
	return att.ContentType() == contentTypeJSON && strings.HasPrefix(att.Filename(), evidenceNotePrefix)
}

// EvidenceStore is the subset of the attachment service the finding-evidence
// endpoints depend on. Implemented by *integration.AttachmentService. Declared
// as an interface so the service is unit-testable without real file storage.
type EvidenceStore interface {
	Upload(ctx context.Context, input integration.UploadInput) (*attachmentdom.Attachment, error)
	ListByContext(ctx context.Context, tenantID shared.ID, contextType, contextID string) ([]*attachmentdom.Attachment, error)
	Download(ctx context.Context, tenantID, attachmentID string) (io.ReadCloser, string, string, error)
	Delete(ctx context.Context, tenantID, attachmentID string) error
}

// SetEvidenceStore wires the attachment-backed evidence store. Safe to call
// after construction; nil disables the finding-evidence endpoints.
func (s *VulnerabilityService) SetEvidenceStore(store EvidenceStore) {
	s.evidenceStore = store
}

// evidenceNote is the on-storage JSON representation of a note-type evidence.
type evidenceNote struct {
	Description string `json:"description"`
	Type        string `json:"type,omitempty"`
	URL         string `json:"url,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`
}

// FindingEvidence is the API-facing view of a piece of evidence attached to a
// finding. A "note" carries a description/type/url; a "file" carries the
// attachment metadata and a download URL.
type FindingEvidence struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // "note" | "file"
	Description string    `json:"description,omitempty"`
	Type        string    `json:"type,omitempty"`
	URL         string    `json:"url,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Size        int64     `json:"size,omitempty"`
	DownloadURL string    `json:"download_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UploadedBy  string    `json:"uploaded_by,omitempty"`
	// UploadedByName is the resolved display name (or email) of the uploader.
	// Best-effort enrichment — left empty when the user cannot be resolved; the
	// UploadedBy UUID is always present for compatibility.
	UploadedByName string `json:"uploaded_by_name,omitempty"`
}

// AddEvidenceInput is the input for attaching a note-type evidence to a finding.
type AddEvidenceInput struct {
	FindingID   string
	TenantID    string
	UserID      string
	Description string
	Type        string
	URL         string
}

// AddFindingEvidence attaches a note-type evidence record to a generic finding.
//
// Authorization: the finding is loaded tenant-scoped and pentest-managed
// findings are rejected (they carry evidence through the pentest module's
// campaign-role gate). This is a NEW, parallel, tenant-scoped path that does
// NOT touch the pentest CheckFindingAccess gate.
func (s *VulnerabilityService) AddFindingEvidence(ctx context.Context, input AddEvidenceInput) (*FindingEvidence, error) {
	if s.evidenceStore == nil {
		return nil, fmt.Errorf("%w: evidence store not configured", shared.ErrValidation)
	}

	description := strings.TrimSpace(input.Description)
	if description == "" {
		return nil, fmt.Errorf("%w: description is required", shared.ErrValidation)
	}
	if len(description) > maxEvidenceDescriptionLen {
		return nil, fmt.Errorf("%w: description exceeds %d characters", shared.ErrValidation, maxEvidenceDescriptionLen)
	}
	evType := strings.TrimSpace(input.Type)
	if len(evType) > maxEvidenceTypeLen {
		return nil, fmt.Errorf("%w: type exceeds %d characters", shared.ErrValidation, maxEvidenceTypeLen)
	}
	evURL := strings.TrimSpace(input.URL)
	if len(evURL) > maxEvidenceURLLen {
		return nil, fmt.Errorf("%w: url exceeds %d characters", shared.ErrValidation, maxEvidenceURLLen)
	}

	// Tenant-scoped load + pentest guard (404/400 on cross-tenant / pentest).
	f, err := s.getFindingWithTenantCheck(ctx, input.FindingID, input.TenantID)
	if err != nil {
		return nil, err
	}

	// Cap manual note-type evidence per finding (analogous to maxRemediationSteps)
	// so a findings:write user cannot loop unbounded notes on one finding.
	existing, err := s.evidenceStore.ListByContext(ctx, f.TenantID(), evidenceContextType, f.ID().String())
	if err != nil {
		return nil, fmt.Errorf("failed to list existing evidence: %w", err)
	}
	noteCount := 0
	for _, att := range existing {
		if isEvidenceNote(att) {
			noteCount++
		}
	}
	if noteCount >= maxEvidenceNotes {
		return nil, fmt.Errorf("%w: a finding may hold at most %d evidence notes", shared.ErrValidation, maxEvidenceNotes)
	}

	payload := evidenceNote{
		Description: description,
		Type:        evType,
		URL:         evURL,
		CreatedBy:   input.UserID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode evidence note: %w", err)
	}

	filename := fmt.Sprintf("%s%s.json", evidenceNotePrefix, shared.NewID().String())
	att, err := s.evidenceStore.Upload(ctx, integration.UploadInput{
		TenantID:    f.TenantID().String(),
		Filename:    filename,
		ContentType: "application/json",
		Size:        int64(len(body)),
		Reader:      bytes.NewReader(body),
		UploadedBy:  input.UserID,
		ContextType: evidenceContextType,
		ContextID:   f.ID().String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store evidence: %w", err)
	}

	s.logger.Info("finding evidence added",
		"finding_id", f.ID().String(), "evidence_id", att.ID().String())

	return &FindingEvidence{
		ID:          att.ID().String(),
		Kind:        "note",
		Description: description,
		Type:        evType,
		URL:         evURL,
		CreatedAt:   att.CreatedAt(),
		UploadedBy:  input.UserID,
	}, nil
}

// ListFindingEvidence returns all evidence attached to a generic finding,
// tenant-scoped. Note records are decoded from storage; any other attachment
// is surfaced as a downloadable file.
func (s *VulnerabilityService) ListFindingEvidence(ctx context.Context, findingID, tenantID string) ([]*FindingEvidence, error) {
	if s.evidenceStore == nil {
		return nil, fmt.Errorf("%w: evidence store not configured", shared.ErrValidation)
	}

	f, err := s.getFindingWithTenantCheck(ctx, findingID, tenantID)
	if err != nil {
		return nil, err
	}

	atts, err := s.evidenceStore.ListByContext(ctx, f.TenantID(), evidenceContextType, f.ID().String())
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence: %w", err)
	}

	out := make([]*FindingEvidence, 0, len(atts))
	for _, att := range atts {
		out = append(out, s.attachmentToEvidence(ctx, f.TenantID(), att))
	}
	s.enrichUploaderNames(ctx, out)
	return out, nil
}

// enrichUploaderNames resolves each evidence record's UploadedBy UUID to a
// display name (falling back to email), batching the lookup into a single
// GetByIDs call. Best-effort: a missing user or a nil userRepo simply leaves
// UploadedByName empty — the UUID stays for compatibility. The UUIDs originate
// from tenant-scoped attachments, so this never crosses the tenant boundary.
func (s *VulnerabilityService) enrichUploaderNames(ctx context.Context, evs []*FindingEvidence) {
	if s.userRepo == nil || len(evs) == 0 {
		return
	}

	seen := make(map[string]struct{}, len(evs))
	ids := make([]shared.ID, 0, len(evs))
	for _, ev := range evs {
		if ev.UploadedBy == "" {
			continue
		}
		if _, dup := seen[ev.UploadedBy]; dup {
			continue
		}
		uid, err := shared.IDFromString(ev.UploadedBy)
		if err != nil {
			continue
		}
		seen[ev.UploadedBy] = struct{}{}
		ids = append(ids, uid)
	}
	if len(ids) == 0 {
		return
	}

	users, err := s.userRepo.GetByIDs(ctx, ids)
	if err != nil {
		s.logger.Warn("failed to resolve evidence uploader names", "error", err)
		return
	}

	nameByID := make(map[string]string, len(users))
	for _, u := range users {
		name := strings.TrimSpace(u.Name())
		if name == "" {
			name = u.Email()
		}
		nameByID[u.ID().String()] = name
	}
	for _, ev := range evs {
		if name, ok := nameByID[ev.UploadedBy]; ok {
			ev.UploadedByName = name
		}
	}
}

// DeleteFindingEvidence removes a note-type evidence record from a generic
// (non-pentest) finding.
//
// Authorization mirrors the add path: the finding is loaded tenant-scoped and
// pentest-managed findings are rejected. The note is then confirmed to belong
// to THIS finding's own attachment context (context_type=finding,
// context_id=findingID, tenant=f.TenantID) BEFORE any delete — an attachment id
// from a different finding or tenant is absent from that list and yields
// ErrNotFound, so we never delete by attachment id alone. Only note-type
// attachments (JSON payload with the evidence-note filename prefix) may be
// removed here; a plain file/pentest attachment sharing the context is refused.
func (s *VulnerabilityService) DeleteFindingEvidence(ctx context.Context, findingID, tenantID, noteID string) error {
	if s.evidenceStore == nil {
		return fmt.Errorf("%w: evidence store not configured", shared.ErrValidation)
	}

	// Tenant-scoped load + pentest guard (404/400 on cross-tenant / pentest).
	f, err := s.getFindingWithTenantCheck(ctx, findingID, tenantID)
	if err != nil {
		return err
	}

	// Cross-finding / cross-tenant guard: only ever inspect THIS finding's own
	// attachment context, so a note belonging elsewhere is simply not found.
	atts, err := s.evidenceStore.ListByContext(ctx, f.TenantID(), evidenceContextType, f.ID().String())
	if err != nil {
		return fmt.Errorf("failed to list evidence: %w", err)
	}

	var target *attachmentdom.Attachment
	for _, att := range atts {
		if att.ID().String() == noteID {
			target = att
			break
		}
	}
	if target == nil {
		return shared.ErrNotFound
	}

	// Refuse to delete anything that is not a note — this endpoint must never
	// remove arbitrary uploaded files that happen to share the finding context.
	if !isEvidenceNote(target) {
		return fmt.Errorf("%w: attachment is not a deletable evidence note", shared.ErrValidation)
	}

	if err := s.evidenceStore.Delete(ctx, f.TenantID().String(), target.ID().String()); err != nil {
		return fmt.Errorf("failed to delete evidence: %w", err)
	}

	s.logger.Info("finding evidence deleted",
		"finding_id", f.ID().String(), "evidence_id", target.ID().String())
	return nil
}

// attachmentToEvidence maps a stored attachment to the evidence view. For note
// records it downloads and decodes the JSON payload; a download/parse failure
// degrades gracefully to a metadata-only file entry rather than failing the
// whole list.
func (s *VulnerabilityService) attachmentToEvidence(ctx context.Context, tenantID shared.ID, att *attachmentdom.Attachment) *FindingEvidence {
	if isEvidenceNote(att) {
		if note, ok := s.readEvidenceNote(ctx, tenantID, att.ID().String()); ok {
			return &FindingEvidence{
				ID:          att.ID().String(),
				Kind:        "note",
				Description: note.Description,
				Type:        note.Type,
				URL:         note.URL,
				CreatedAt:   att.CreatedAt(),
				UploadedBy:  att.UploadedBy().String(),
			}
		}
		s.logger.Warn("failed to decode evidence note; returning metadata only",
			"evidence_id", att.ID().String())
	}
	return &FindingEvidence{
		ID:          att.ID().String(),
		Kind:        "file",
		Filename:    att.Filename(),
		ContentType: att.ContentType(),
		Size:        att.Size(),
		DownloadURL: att.URL(),
		CreatedAt:   att.CreatedAt(),
		UploadedBy:  att.UploadedBy().String(),
	}
}

func (s *VulnerabilityService) readEvidenceNote(ctx context.Context, tenantID shared.ID, attachmentID string) (evidenceNote, bool) {
	reader, _, _, err := s.evidenceStore.Download(ctx, tenantID.String(), attachmentID)
	if err != nil {
		return evidenceNote{}, false
	}
	defer func() { _ = reader.Close() }()

	// Notes are tiny; cap the read defensively.
	body, err := io.ReadAll(io.LimitReader(reader, maxEvidenceDescriptionLen+maxEvidenceTypeLen+maxEvidenceURLLen+1024))
	if err != nil {
		return evidenceNote{}, false
	}
	var note evidenceNote
	if err := json.Unmarshal(body, &note); err != nil {
		return evidenceNote{}, false
	}
	return note, true
}

// AddRemediationStep appends a single remediation step to a generic finding,
// preserving any existing steps. Returns the updated step list.
//
// Load-existing → append → persist the whole slice (never wipes prior steps).
func (s *VulnerabilityService) AddRemediationStep(ctx context.Context, findingID, tenantID, step string) ([]string, error) {
	trimmed := strings.TrimSpace(step)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: step is required", shared.ErrValidation)
	}
	if len(trimmed) > maxRemediationStepLen {
		return nil, fmt.Errorf("%w: step exceeds %d characters", shared.ErrValidation, maxRemediationStepLen)
	}

	f, err := s.getFindingWithTenantCheck(ctx, findingID, tenantID)
	if err != nil {
		return nil, err
	}

	// Load-existing remediation so we append rather than overwrite.
	rem := f.Remediation()
	var updated vulnerability.FindingRemediation
	if rem != nil {
		updated = *rem
	}
	if len(updated.Steps) >= maxRemediationSteps {
		return nil, fmt.Errorf("%w: a finding may hold at most %d remediation steps", shared.ErrValidation, maxRemediationSteps)
	}

	// Copy-then-append so we never mutate the entity's backing slice in place.
	steps := make([]string, 0, len(updated.Steps)+1)
	steps = append(steps, updated.Steps...)
	steps = append(steps, trimmed)
	updated.Steps = steps

	f.SetRemediation(&updated)

	if err := s.findingRepo.Update(ctx, f); err != nil {
		return nil, fmt.Errorf("failed to add remediation step: %w", err)
	}

	s.logger.Info("finding remediation step added",
		"finding_id", f.ID().String(), "step_count", len(steps))
	return steps, nil
}
