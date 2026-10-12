package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memAttRepo is an in-memory, tenant-scoped attachment repository.
type memAttRepo struct {
	mu   sync.Mutex
	rows map[shared.ID]*attachment.Attachment
}

func (m *memAttRepo) Create(_ context.Context, a *attachment.Attachment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[a.ID()] = a
	return nil
}

func (m *memAttRepo) GetByID(_ context.Context, tid, id shared.ID) (*attachment.Attachment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.rows[id]; ok && a.TenantID() == tid {
		return a, nil
	}
	return nil, attachment.ErrNotFound
}

func (m *memAttRepo) Delete(_ context.Context, tid, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, id)
	return nil
}

func (m *memAttRepo) ListByContext(context.Context, shared.ID, string, string) ([]*attachment.Attachment, error) {
	return nil, nil
}

func (m *memAttRepo) LinkToContext(context.Context, shared.ID, []shared.ID, shared.ID, string, string) (int64, error) {
	return 0, nil
}

func (m *memAttRepo) FindByHash(context.Context, shared.ID, string, string, string) (*attachment.Attachment, error) {
	return nil, nil
}

func (m *memAttRepo) TotalSize(_ context.Context, tid shared.ID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, a := range m.rows {
		if a.TenantID() == tid {
			n += a.Size()
		}
	}
	return n, nil
}

func newUploadHandler(t *testing.T, quota int64) *AttachmentHandler {
	t.Helper()
	log := logger.New(logger.Config{Level: "error", Format: "text"})
	svc := integration.NewAttachmentService(&memAttRepo{rows: map[shared.ID]*attachment.Attachment{}},
		storage.NewLocalStorage(t.TempDir()), log)
	svc.SetTenantQuota(quota)
	return NewAttachmentHandler(svc, log)
}

func asMember(r *http.Request, tenantID, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
	return r.WithContext(ctx)
}

// uploadReq builds a multipart upload whose file part declares declaredType.
func uploadReq(t *testing.T, filename, declaredType string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="file"; filename="`+filename+`"`)
	h.Set("Content-Type", declaredType)
	part, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(content)
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/attachments", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// The stored type comes from the bytes: an HTML page declared as a PNG is
// refused, whatever the part header says.
func TestAttachmentUpload_TypeFromContentNotDeclaration(t *testing.T) {
	h := newUploadHandler(t, 0)
	tenant, user := shared.NewID().String(), shared.NewID().String()

	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "shot.png", "image/png", []byte("<html><script>alert(1)</script></html>")), tenant, user))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HTML declared as image/png: code %d, want 400 (%s)", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01")
	h.Upload(rec, asMember(uploadReq(t, "shot.png", "text/html", png), tenant, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("PNG declared as text/html: code %d, want 201 (%s)", rec.Code, rec.Body)
	}
	var out struct {
		ContentType string `json:"content_type"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.ContentType != "image/png" {
		t.Fatalf("stored type %q, want image/png", out.ContentType)
	}
}

// Over the organization's quota: 413 STORAGE_QUOTA_EXCEEDED; another
// organization is unaffected; and a file of one organization is not found
// from another.
func TestAttachmentUpload_QuotaAndTenantIsolation(t *testing.T) {
	h := newUploadHandler(t, 32)
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	user := shared.NewID().String()

	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "a.txt", "text/plain", bytes.Repeat([]byte("a"), 30)), tenantA, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first upload: %d %s", rec.Code, rec.Body)
	}
	var first struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &first)

	rec = httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "b.txt", "text/plain", bytes.Repeat([]byte("b"), 10)), tenantA, user))
	if rec.Code != http.StatusRequestEntityTooLarge || !bytes.Contains(rec.Body.Bytes(), []byte("STORAGE_QUOTA_EXCEEDED")) {
		t.Fatalf("over quota: %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "c.txt", "text/plain", bytes.Repeat([]byte("c"), 30)), tenantB, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("other organization refused: %d %s", rec.Code, rec.Body)
	}

	// Tenant B asks for tenant A's attachment id.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+first.ID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", first.ID)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	rec = httptest.NewRecorder()
	h.Download(rec, asMember(r, tenantB, user))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant download: %d, want 404", rec.Code)
	}
}
