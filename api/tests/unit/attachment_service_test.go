package unit

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// =============================================================================
// Mocks
// =============================================================================

type mockAttRepo struct {
	store     map[string]*attachment.Attachment
	createErr error
}

func newMockAttRepo() *mockAttRepo {
	return &mockAttRepo{store: make(map[string]*attachment.Attachment)}
}

func (m *mockAttRepo) Create(_ context.Context, att *attachment.Attachment) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.store[att.ID().String()] = att
	return nil
}

func (m *mockAttRepo) GetByID(_ context.Context, tid, id shared.ID) (*attachment.Attachment, error) {
	att, ok := m.store[id.String()]
	if !ok || att.TenantID() != tid {
		return nil, attachment.ErrNotFound
	}
	return att, nil
}

func (m *mockAttRepo) Delete(_ context.Context, tid, id shared.ID) error {
	att, ok := m.store[id.String()]
	if !ok || att.TenantID() != tid {
		return attachment.ErrNotFound
	}
	delete(m.store, id.String())
	return nil
}

func (m *mockAttRepo) ListByContext(_ context.Context, tid shared.ID, ct, cid string) ([]*attachment.Attachment, error) {
	var r []*attachment.Attachment
	for _, a := range m.store {
		if a.TenantID() == tid && a.ContextType() == ct && a.ContextID() == cid {
			r = append(r, a)
		}
	}
	return r, nil
}

func (m *mockAttRepo) FindByHash(_ context.Context, tid shared.ID, ct, cid, hash string) (*attachment.Attachment, error) {
	for _, a := range m.store {
		if a.TenantID() == tid && a.ContextType() == ct && a.ContextID() == cid && a.ContentHash() == hash {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockAttRepo) LinkToContext(_ context.Context, tid shared.ID, ids []shared.ID, uid shared.ID, ct, cid string) (int64, error) {
	var n int64
	for _, id := range ids {
		if a, ok := m.store[id.String()]; ok && a.TenantID() == tid && a.UploadedBy() == uid && a.ContextID() == "" {
			n++
		}
	}
	return n, nil
}

type mockAttStorage struct {
	files    map[string]string // key → content
	tenantOf map[string]string // key → tenant
	eraseErr error
	erased   []string
}

func newMockAttStorage() *mockAttStorage {
	return &mockAttStorage{files: make(map[string]string), tenantOf: make(map[string]string)}
}

func (m *mockAttStorage) Upload(_ context.Context, tenantID, filename, _ string, r io.Reader) (string, error) {
	data, _ := io.ReadAll(r)
	key := shared.NewID().String() + "_" + filename
	m.files[key] = string(data)
	m.tenantOf[key] = tenantID
	return key, nil
}

func (m *mockAttStorage) EraseTenant(_ context.Context, tenantID string) (int, error) {
	if m.eraseErr != nil {
		return 0, m.eraseErr
	}
	m.erased = append(m.erased, tenantID)
	n := 0
	for k, t := range m.tenantOf {
		if t == tenantID {
			delete(m.files, k)
			delete(m.tenantOf, k)
			n++
		}
	}
	return n, nil
}

func (m *mockAttStorage) Download(_ context.Context, _, key string) (io.ReadCloser, string, error) {
	if _, ok := m.files[key]; !ok {
		return nil, "", attachment.ErrNotFound
	}
	return io.NopCloser(strings.NewReader(m.files[key])), "", nil
}

func (m *mockAttStorage) Delete(_ context.Context, _, key string) error {
	delete(m.files, key)
	return nil
}

// =============================================================================
// Helper
// =============================================================================

func newAttSvc() (*integration.AttachmentService, *mockAttRepo, *mockAttStorage) {
	repo := newMockAttRepo()
	st := newMockAttStorage()
	log := logger.New(logger.Config{Level: "error", Format: "text"})
	return integration.NewAttachmentService(repo, st, log), repo, st
}

var (
	attTID = shared.NewID().String()
	attUID = shared.NewID().String()
	attCID = shared.NewID().String()
)

func mkUpload() integration.UploadInput {
	return integration.UploadInput{
		TenantID: attTID, Filename: "shot.png", ContentType: "image/png",
		Size: 1024, Reader: strings.NewReader("fakepng"), UploadedBy: attUID,
		ContextType: "finding", ContextID: attCID,
	}
}

// =============================================================================
// Upload
// =============================================================================

func TestAtt_Upload_Valid(t *testing.T) {
	svc, repo, _ := newAttSvc()
	att, err := svc.Upload(context.Background(), mkUpload())
	require.NoError(t, err)
	assert.Equal(t, "shot.png", att.Filename())
	assert.NotEmpty(t, att.ContentHash())
	assert.Equal(t, "local", att.StorageProvider())
	assert.Equal(t, 1, len(repo.store))
}

func TestAtt_Upload_TooLarge(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.Size = 11 * 1024 * 1024
	_, err := svc.Upload(context.Background(), in)
	assert.ErrorIs(t, err, attachment.ErrTooLarge)
}

func TestAtt_Upload_UnsupportedType(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.ContentType = "application/x-executable"
	_, err := svc.Upload(context.Background(), in)
	assert.ErrorIs(t, err, attachment.ErrUnsupported)
}

func TestAtt_Upload_SVG_Blocked(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.ContentType = "image/svg+xml"
	_, err := svc.Upload(context.Background(), in)
	assert.ErrorIs(t, err, attachment.ErrUnsupported)
}

func TestAtt_Upload_Dedup_SameContext(t *testing.T) {
	svc, _, _ := newAttSvc()
	a1, _ := svc.Upload(context.Background(), mkUpload())
	in2 := mkUpload() // same content + same context
	a2, _ := svc.Upload(context.Background(), in2)
	assert.Equal(t, a1.ID().String(), a2.ID().String()) // dedup
}

func TestAtt_Upload_NoDedup_DifferentContext(t *testing.T) {
	svc, _, _ := newAttSvc()
	a1, _ := svc.Upload(context.Background(), mkUpload())
	in2 := mkUpload()
	in2.ContextID = shared.NewID().String()
	a2, _ := svc.Upload(context.Background(), in2)
	assert.NotEqual(t, a1.ID().String(), a2.ID().String())
}

func TestAtt_Upload_EmptyContext(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.ContextID = ""
	att, err := svc.Upload(context.Background(), in)
	require.NoError(t, err)
	assert.Empty(t, att.ContextID())
}

func TestAtt_Upload_InvalidTenant(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.TenantID = "bad"
	_, err := svc.Upload(context.Background(), in)
	assert.Error(t, err)
}

// =============================================================================
// Download
// =============================================================================

func TestAtt_Download_Valid(t *testing.T) {
	svc, _, _ := newAttSvc()
	att, _ := svc.Upload(context.Background(), mkUpload())
	r, ct, fn, err := svc.Download(context.Background(), attTID, att.ID().String())
	require.NoError(t, err)
	defer r.Close()
	assert.Equal(t, "image/png", ct)
	assert.Equal(t, "shot.png", fn)
}

func TestAtt_Download_NotFound(t *testing.T) {
	svc, _, _ := newAttSvc()
	_, _, _, err := svc.Download(context.Background(), attTID, shared.NewID().String())
	assert.ErrorIs(t, err, attachment.ErrNotFound)
}

// =============================================================================
// Delete
// =============================================================================

func TestAtt_Delete_Valid(t *testing.T) {
	svc, repo, _ := newAttSvc()
	att, _ := svc.Upload(context.Background(), mkUpload())
	require.Equal(t, 1, len(repo.store))
	err := svc.Delete(context.Background(), attTID, att.ID().String())
	require.NoError(t, err)
	assert.Equal(t, 0, len(repo.store))
}

func TestAtt_Delete_NotFound(t *testing.T) {
	svc, _, _ := newAttSvc()
	err := svc.Delete(context.Background(), attTID, shared.NewID().String())
	assert.ErrorIs(t, err, attachment.ErrNotFound)
}

// =============================================================================
// Link
// =============================================================================

func TestAtt_Link_Valid(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := mkUpload()
	in.ContextID = ""
	att, _ := svc.Upload(context.Background(), in)
	n, err := svc.LinkToContext(context.Background(), attTID, attUID, []string{att.ID().String()}, "finding", attCID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestAtt_Link_Empty(t *testing.T) {
	svc, _, _ := newAttSvc()
	n, err := svc.LinkToContext(context.Background(), attTID, attUID, []string{}, "finding", attCID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// =============================================================================
// Entity
// =============================================================================

func TestAtt_Entity_Reconstitute(t *testing.T) {
	id, tid, uid := shared.NewID(), shared.NewID(), shared.NewID()
	now := time.Now().UTC()
	att := attachment.ReconstituteAttachment(id, tid, "f.jpg", "image/jpeg", 2048, "k1", uid, "finding", "c1", "h256", "s3", now)
	assert.Equal(t, id, att.ID())
	assert.Equal(t, "s3", att.StorageProvider())
	assert.Equal(t, "h256", att.ContentHash())
}

func TestAtt_Entity_MarkdownLink_Image(t *testing.T) {
	att := attachment.NewAttachment(shared.NewID(), "x.png", "image/png", 100, "k", shared.NewID(), "", "")
	assert.Contains(t, att.MarkdownLink(), "![x.png]")
}

func TestAtt_Entity_MarkdownLink_NonImage(t *testing.T) {
	att := attachment.NewAttachment(shared.NewID(), "r.pdf", "application/pdf", 100, "k", shared.NewID(), "", "")
	assert.Contains(t, att.MarkdownLink(), "[r.pdf]")
	assert.NotContains(t, att.MarkdownLink(), "![")
}

// =============================================================================
// EraseTenant (organization deletion)
// =============================================================================

type stubStorageResolver struct {
	cfg *attachment.StorageConfig
	err error
}

func (r stubStorageResolver) GetTenantStorageConfig(context.Context, string) (*attachment.StorageConfig, error) {
	return r.cfg, r.err
}

func uploadFor(t *testing.T, svc *integration.AttachmentService, tenantID string) {
	t.Helper()
	_, err := svc.Upload(context.Background(), integration.UploadInput{
		TenantID: tenantID, Filename: "evidence.txt", ContentType: "text/plain", Size: 5,
		Reader: strings.NewReader("hello"), UploadedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
}

// Erasing tenant A removes A's files from the server storage and A's own
// bucket, and never touches tenant B's files.
func TestAtt_EraseTenant_OnlyThatTenantEveryBackend(t *testing.T) {
	svc, _, operator := newAttSvc()
	own := newMockAttStorage()
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	uploadFor(t, svc, tenantA)
	uploadFor(t, svc, tenantB)

	svc.SetTenantStorageResolver(
		stubStorageResolver{cfg: &attachment.StorageConfig{Provider: attachment.ProviderS3, Bucket: "tenant-bucket"}},
		func(attachment.StorageConfig) (attachment.FileStorage, error) { return own, nil })
	// A file of A in its own bucket, and one of B there too.
	_, _ = own.Upload(context.Background(), tenantA, "a.txt", "text/plain", strings.NewReader("a"))
	_, _ = own.Upload(context.Background(), tenantB, "b.txt", "text/plain", strings.NewReader("b"))

	n, err := svc.EraseTenant(context.Background(), tenantA)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []string{tenantA}, operator.erased)
	assert.Equal(t, []string{tenantA}, own.erased)
	for _, tid := range operator.tenantOf {
		assert.Equal(t, tenantB, tid, "a file of tenant A is left on the server storage")
	}
	for _, tid := range own.tenantOf {
		assert.Equal(t, tenantB, tid, "a file of tenant A is left in its own bucket")
	}
	assert.Len(t, operator.files, 1, "tenant B's file must survive")
	assert.Len(t, own.files, 1, "tenant B's file must survive")
}

// Any backend that cannot be erased fails the erasure, so the organization
// deletion is refused rather than losing track of the files.
func TestAtt_EraseTenant_FailsClosed(t *testing.T) {
	tenantA := shared.NewID().String()
	local := attachment.StorageConfig{Provider: attachment.ProviderS3, Bucket: "b"}

	t.Run("server storage down", func(t *testing.T) {
		svc, _, operator := newAttSvc()
		operator.eraseErr = assert.AnError
		_, err := svc.EraseTenant(context.Background(), tenantA)
		require.Error(t, err)
	})
	t.Run("storage setting unreadable", func(t *testing.T) {
		svc, _, _ := newAttSvc()
		svc.SetTenantStorageResolver(stubStorageResolver{err: assert.AnError},
			func(attachment.StorageConfig) (attachment.FileStorage, error) { return newMockAttStorage(), nil })
		_, err := svc.EraseTenant(context.Background(), tenantA)
		require.Error(t, err)
	})
	t.Run("own bucket cannot be opened", func(t *testing.T) {
		svc, _, _ := newAttSvc()
		svc.SetTenantStorageResolver(stubStorageResolver{cfg: &local},
			func(attachment.StorageConfig) (attachment.FileStorage, error) { return nil, assert.AnError })
		_, err := svc.EraseTenant(context.Background(), tenantA)
		require.Error(t, err)
	})
	t.Run("own bucket refuses", func(t *testing.T) {
		svc, _, _ := newAttSvc()
		own := newMockAttStorage()
		own.eraseErr = assert.AnError
		svc.SetTenantStorageResolver(stubStorageResolver{cfg: &local},
			func(attachment.StorageConfig) (attachment.FileStorage, error) { return own, nil })
		_, err := svc.EraseTenant(context.Background(), tenantA)
		require.Error(t, err)
	})
}

// A value that is not a canonical tenant id is never used as a namespace: an
// empty one would be the whole store.
func TestAtt_EraseTenant_RefusesNonTenantNamespace(t *testing.T) {
	svc, _, operator := newAttSvc()
	upper := strings.ToUpper(shared.NewID().String())
	for _, bad := range []string{"", "..", "/", "tenant-1", "00000000-0000-0000-0000-000000000000", upper} {
		_, err := svc.EraseTenant(context.Background(), bad)
		assert.Error(t, err, "namespace %q", bad)
	}
	assert.Empty(t, operator.erased)
}
