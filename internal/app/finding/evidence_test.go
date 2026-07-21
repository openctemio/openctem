package finding

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/openctemio/api/internal/app/integration"
	attachmentdom "github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// stubUserRepo implements only GetByIDs (the sole method the evidence
// name-resolution path uses). The embedded nil interface satisfies the rest of
// user.Repository; any un-overridden call panics (intended).
type stubUserRepo struct {
	user.Repository
	byID map[string]*user.User
}

func (r *stubUserRepo) GetByIDs(_ context.Context, ids []shared.ID) ([]*user.User, error) {
	out := make([]*user.User, 0, len(ids))
	for _, id := range ids {
		if u, ok := r.byID[id.String()]; ok {
			out = append(out, u)
		}
	}
	return out, nil
}

// stubFindingRepo implements only the methods the evidence/steps paths need.
// The embedded nil interface satisfies the rest of vulnerability.FindingRepository;
// calling any un-overridden method panics (intended — tests must not).
type stubFindingRepo struct {
	vulnerability.FindingRepository
	byID    map[string]*vulnerability.Finding
	updated *vulnerability.Finding
	updErr  error
}

func (s *stubFindingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	f, ok := s.byID[tenantID.String()+"/"+id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return f, nil
}

func (s *stubFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	if s.updErr != nil {
		return s.updErr
	}
	s.updated = f
	return nil
}

// stubEvidenceStore is an in-memory EvidenceStore.
type stubEvidenceStore struct {
	uploads   []integration.UploadInput
	blobs     map[string][]byte // attachmentID -> body
	byContext map[string][]*attachmentdom.Attachment
	uploadErr error
}

func newStubEvidenceStore() *stubEvidenceStore {
	return &stubEvidenceStore{blobs: map[string][]byte{}, byContext: map[string][]*attachmentdom.Attachment{}}
}

func ctxKey(ct, cid string) string { return ct + "/" + cid }

func (s *stubEvidenceStore) Upload(_ context.Context, in integration.UploadInput) (*attachmentdom.Attachment, error) {
	if s.uploadErr != nil {
		return nil, s.uploadErr
	}
	s.uploads = append(s.uploads, in)
	body, _ := io.ReadAll(in.Reader)
	tid, _ := shared.IDFromString(in.TenantID)
	uid, _ := shared.IDFromString(in.UploadedBy)
	att := attachmentdom.NewAttachment(tid, in.Filename, in.ContentType, in.Size, "key/"+in.Filename, uid, in.ContextType, in.ContextID)
	s.blobs[att.ID().String()] = body
	key := ctxKey(in.ContextType, in.ContextID)
	s.byContext[key] = append(s.byContext[key], att)
	return att, nil
}

func (s *stubEvidenceStore) ListByContext(_ context.Context, _ shared.ID, ct, cid string) ([]*attachmentdom.Attachment, error) {
	return s.byContext[ctxKey(ct, cid)], nil
}

func (s *stubEvidenceStore) Download(_ context.Context, _, attachmentID string) (io.ReadCloser, string, string, error) {
	body, ok := s.blobs[attachmentID]
	if !ok {
		return nil, "", "", shared.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(body)), "application/json", "note.json", nil
}

func (s *stubEvidenceStore) Delete(_ context.Context, _, attachmentID string) error {
	if _, ok := s.blobs[attachmentID]; !ok {
		return shared.ErrNotFound
	}
	delete(s.blobs, attachmentID)
	for key, atts := range s.byContext {
		kept := atts[:0]
		for _, att := range atts {
			if att.ID().String() != attachmentID {
				kept = append(kept, att)
			}
		}
		s.byContext[key] = kept
	}
	return nil
}

// addFileAttachment seeds a non-note (plain file) attachment into a finding's
// context so tests can assert the delete path refuses it.
func (s *stubEvidenceStore) addFileAttachment(tenantID shared.ID, contextID string) *attachmentdom.Attachment {
	att := attachmentdom.NewAttachment(tenantID, "screenshot.png", "image/png", 123, "key/screenshot.png", shared.NewID(), evidenceContextType, contextID)
	s.blobs[att.ID().String()] = []byte("png")
	key := ctxKey(evidenceContextType, contextID)
	s.byContext[key] = append(s.byContext[key], att)
	return att
}

func newTestService(repo vulnerability.FindingRepository, store EvidenceStore) *VulnerabilityService {
	return &VulnerabilityService{
		findingRepo:   repo,
		evidenceStore: store,
		logger:        logger.NewNop(),
	}
}

func mkFinding(t *testing.T, tenantID shared.ID, src vulnerability.FindingSource) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, shared.NewID(), src, "nuclei", vulnerability.SeverityHigh, "test finding")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func seedRepo(f *vulnerability.Finding) *stubFindingRepo {
	return &stubFindingRepo{byID: map[string]*vulnerability.Finding{
		f.TenantID().String() + "/" + f.ID().String(): f,
	}}
}

// --- Evidence ---------------------------------------------------------------

func TestAddFindingEvidence_HappyPath(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	ev, err := s.AddFindingEvidence(context.Background(), AddEvidenceInput{
		FindingID:   f.ID().String(),
		TenantID:    tenantID.String(),
		UserID:      shared.NewID().String(),
		Description: "SQLi confirmed via error-based payload",
		Type:        "note",
		URL:         "https://example.com/poc",
	})
	if err != nil {
		t.Fatalf("AddFindingEvidence: %v", err)
	}
	if ev.Kind != "note" || ev.Description == "" {
		t.Fatalf("unexpected evidence: %+v", ev)
	}
	if len(store.uploads) != 1 {
		t.Fatalf("expected 1 upload, got %d", len(store.uploads))
	}
	up := store.uploads[0]
	if up.ContextType != "finding" || up.ContextID != f.ID().String() {
		t.Fatalf("evidence not stored tenant/finding-scoped: ct=%s cid=%s", up.ContextType, up.ContextID)
	}
	if up.TenantID != tenantID.String() {
		t.Fatalf("evidence stored under wrong tenant: %s", up.TenantID)
	}

	// GET round-trip: the note is retrievable and decoded.
	list, err := s.ListFindingEvidence(context.Background(), f.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("ListFindingEvidence: %v", err)
	}
	if len(list) != 1 || list[0].Description != "SQLi confirmed via error-based payload" || list[0].URL != "https://example.com/poc" {
		t.Fatalf("evidence not retrievable/decoded: %+v", list)
	}
}

func TestAddFindingEvidence_CrossTenantIsNotFound(t *testing.T) {
	ownerTenant := shared.NewID()
	f := mkFinding(t, ownerTenant, vulnerability.FindingSourceDAST)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	otherTenant := shared.NewID()
	_, err := s.AddFindingEvidence(context.Background(), AddEvidenceInput{
		FindingID:   f.ID().String(),
		TenantID:    otherTenant.String(), // different tenant
		UserID:      shared.NewID().String(),
		Description: "should not work",
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant evidence add: want ErrNotFound, got %v", err)
	}
}

func TestAddFindingEvidence_PentestFindingRejected(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourcePentest)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	_, err := s.AddFindingEvidence(context.Background(), AddEvidenceInput{
		FindingID:   f.ID().String(),
		TenantID:    tenantID.String(),
		UserID:      shared.NewID().String(),
		Description: "pentest evidence must go through the pentest module",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("pentest finding on generic evidence path: want ErrValidation, got %v", err)
	}
}

func TestAddFindingEvidence_EmptyDescription(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	_, err := s.AddFindingEvidence(context.Background(), AddEvidenceInput{
		FindingID:   f.ID().String(),
		TenantID:    tenantID.String(),
		Description: "   ",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty description: want ErrValidation, got %v", err)
	}
}

func addNote(t *testing.T, s *VulnerabilityService, f *vulnerability.Finding, tenantID, userID shared.ID) *FindingEvidence {
	t.Helper()
	ev, err := s.AddFindingEvidence(context.Background(), AddEvidenceInput{
		FindingID:   f.ID().String(),
		TenantID:    tenantID.String(),
		UserID:      userID.String(),
		Description: "note body",
	})
	if err != nil {
		t.Fatalf("AddFindingEvidence: %v", err)
	}
	return ev
}

func TestDeleteFindingEvidence_HappyPath(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	ev := addNote(t, s, f, tenantID, shared.NewID())

	if err := s.DeleteFindingEvidence(context.Background(), f.ID().String(), tenantID.String(), ev.ID); err != nil {
		t.Fatalf("DeleteFindingEvidence: %v", err)
	}

	list, err := s.ListFindingEvidence(context.Background(), f.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("ListFindingEvidence: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected note removed, still have %d", len(list))
	}
}

func TestDeleteFindingEvidence_CrossTenantIsNotFound(t *testing.T) {
	ownerTenant := shared.NewID()
	f := mkFinding(t, ownerTenant, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	ev := addNote(t, s, f, ownerTenant, shared.NewID())

	// A different tenant must not resolve the finding at all → 404, note stays.
	err := s.DeleteFindingEvidence(context.Background(), f.ID().String(), shared.NewID().String(), ev.ID)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: want ErrNotFound, got %v", err)
	}
	if _, ok := store.blobs[ev.ID]; !ok {
		t.Fatalf("note was deleted on a cross-tenant request")
	}
}

func TestDeleteFindingEvidence_NoteOfDifferentFindingIsNotFound(t *testing.T) {
	tenantID := shared.NewID()
	f1 := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	f2 := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	// Seed both findings under the same repo/tenant.
	repo := &stubFindingRepo{byID: map[string]*vulnerability.Finding{
		f1.TenantID().String() + "/" + f1.ID().String(): f1,
		f2.TenantID().String() + "/" + f2.ID().String(): f2,
	}}
	s := newTestService(repo, store)

	// Note belongs to f2.
	ev := addNote(t, s, f2, tenantID, shared.NewID())

	// Deleting via f1 must not touch f2's note.
	err := s.DeleteFindingEvidence(context.Background(), f1.ID().String(), tenantID.String(), ev.ID)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-finding delete: want ErrNotFound, got %v", err)
	}
	if _, ok := store.blobs[ev.ID]; !ok {
		t.Fatalf("note of a different finding was deleted")
	}
}

func TestDeleteFindingEvidence_NonNoteAttachmentRefused(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	file := store.addFileAttachment(tenantID, f.ID().String())

	err := s.DeleteFindingEvidence(context.Background(), f.ID().String(), tenantID.String(), file.ID().String())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("non-note delete: want ErrValidation, got %v", err)
	}
	if _, ok := store.blobs[file.ID().String()]; !ok {
		t.Fatalf("non-note attachment was deleted")
	}
}

func TestDeleteFindingEvidence_PentestFindingRejected(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourcePentest)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	err := s.DeleteFindingEvidence(context.Background(), f.ID().String(), tenantID.String(), shared.NewID().String())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("pentest finding on generic delete path: want ErrValidation, got %v", err)
	}
}

// --- Uploader name resolution ----------------------------------------------

func TestListFindingEvidence_ResolvesUploaderName(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	uploader := shared.NewID()
	u, err := user.NewLocalUserWithID(uploader, "alice@example.com", "Alice Analyst")
	if err != nil {
		t.Fatalf("NewLocalUserWithID: %v", err)
	}
	s.SetUserRepository(&stubUserRepo{byID: map[string]*user.User{uploader.String(): u}})

	addNote(t, s, f, tenantID, uploader)

	list, err := s.ListFindingEvidence(context.Background(), f.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("ListFindingEvidence: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(list))
	}
	if list[0].UploadedBy != uploader.String() {
		t.Fatalf("UploadedBy UUID dropped: %q", list[0].UploadedBy)
	}
	if list[0].UploadedByName != "Alice Analyst" {
		t.Fatalf("UploadedByName = %q, want Alice Analyst", list[0].UploadedByName)
	}
}

func TestListFindingEvidence_MissingUploaderToleratesGracefully(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	store := newStubEvidenceStore()
	s := newTestService(seedRepo(f), store)

	// Empty user repo → uploader cannot be resolved; UUID must remain, name empty.
	s.SetUserRepository(&stubUserRepo{byID: map[string]*user.User{}})

	uploader := shared.NewID()
	addNote(t, s, f, tenantID, uploader)

	list, err := s.ListFindingEvidence(context.Background(), f.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("ListFindingEvidence: %v", err)
	}
	if len(list) != 1 || list[0].UploadedBy != uploader.String() {
		t.Fatalf("expected UUID preserved, got %+v", list)
	}
	if list[0].UploadedByName != "" {
		t.Fatalf("UploadedByName should be empty for unknown user, got %q", list[0].UploadedByName)
	}
}

// --- Remediation steps ------------------------------------------------------

func TestAddRemediationStep_AppendsPreservingExisting(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	f.SetRemediation(&vulnerability.FindingRemediation{
		Recommendation: "upgrade the library",
		Steps:          []string{"step one", "step two"},
	})
	repo := seedRepo(f)
	s := newTestService(repo, newStubEvidenceStore())

	steps, err := s.AddRemediationStep(context.Background(), f.ID().String(), tenantID.String(), "step three")
	if err != nil {
		t.Fatalf("AddRemediationStep: %v", err)
	}
	want := []string{"step one", "step two", "step three"}
	if len(steps) != len(want) {
		t.Fatalf("steps = %v, want %v", steps, want)
	}
	for i := range want {
		if steps[i] != want[i] {
			t.Fatalf("steps[%d] = %q, want %q", i, steps[i], want[i])
		}
	}
	// Existing remediation fields must be preserved.
	if repo.updated == nil || repo.updated.Remediation().Recommendation != "upgrade the library" {
		t.Fatalf("recommendation clobbered: %+v", repo.updated.Remediation())
	}
}

func TestAddRemediationStep_FirstStepOnNilRemediation(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	steps, err := s.AddRemediationStep(context.Background(), f.ID().String(), tenantID.String(), "first step")
	if err != nil {
		t.Fatalf("AddRemediationStep: %v", err)
	}
	if len(steps) != 1 || steps[0] != "first step" {
		t.Fatalf("steps = %v, want [first step]", steps)
	}
}

func TestAddRemediationStep_EmptyRejected(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	_, err := s.AddRemediationStep(context.Background(), f.ID().String(), tenantID.String(), "  ")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty step: want ErrValidation, got %v", err)
	}
}

func TestAddRemediationStep_CrossTenantIsNotFound(t *testing.T) {
	ownerTenant := shared.NewID()
	f := mkFinding(t, ownerTenant, vulnerability.FindingSourceDAST)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	_, err := s.AddRemediationStep(context.Background(), f.ID().String(), shared.NewID().String(), "step")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant step add: want ErrNotFound, got %v", err)
	}
}

func TestAddRemediationStep_PentestFindingRejected(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourcePentest)
	s := newTestService(seedRepo(f), newStubEvidenceStore())

	_, err := s.AddRemediationStep(context.Background(), f.ID().String(), tenantID.String(), "step")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("pentest finding on generic step path: want ErrValidation, got %v", err)
	}
}
