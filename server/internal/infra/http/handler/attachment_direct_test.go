package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// signingStore is a local store that signs like a bucket would.
type signingStore struct {
	*storage.LocalStorage
	signed []string
}

func (s *signingStore) PresignDownload(_ context.Context, tenantID, key, _, _ string, ttl time.Duration) (string, error) {
	s.signed = append(s.signed, tenantID+"/"+key)
	return "https://bucket.example.com/" + tenantID + "/" + key + "?X-Amz-Expires=" + ttl.String(), nil
}

func newDirectHandler(t *testing.T, store attachment.FileStorage, on bool) (*AttachmentHandler, *memAttRepo) {
	t.Helper()
	log := logger.New(logger.Config{Level: "error", Format: "text"})
	repo := &memAttRepo{rows: map[shared.ID]*attachment.Attachment{}}
	svc := integration.NewAttachmentService(repo, store, log)
	svc.SetDirectDownloads(on)
	return NewAttachmentHandler(svc, log), repo
}

func uploadText(t *testing.T, h *AttachmentHandler, tenant, user string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "notes.txt", "text/plain", []byte("evidence notes")), tenant, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func getDownloadURL(h *AttachmentHandler, id, tenant, user string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+id+"/signed-url", nil)
	h.DownloadURL(rec, withID(asMember(r, tenant, user), id))
	return rec
}

// A signed URL is handed out for the caller's own tenant's file only, after
// the same lookup as a download; it is never cached, never for a flagged
// file, and not at all when turned off or on a store that cannot sign.
func TestAttachmentDownloadURL(t *testing.T) {
	store := &signingStore{LocalStorage: storage.NewLocalStorage(t.TempDir())}
	h, repo := newDirectHandler(t, store, true)
	tenant, user := shared.NewID().String(), shared.NewID().String()
	id := uploadText(t, h, tenant, user)

	rec := getDownloadURL(h, id, tenant, user)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed-url: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		URL       string    `json:"url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !strings.HasPrefix(out.URL, "https://bucket.example.com/"+tenant+"/") || time.Until(out.ExpiresAt) > time.Minute+time.Second {
		t.Errorf("url %q expires %v", out.URL, out.ExpiresAt)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", rec.Header())
	}

	if rec := getDownloadURL(h, id, shared.NewID().String(), user); rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant: %d", rec.Code)
	}
	if len(store.signed) != 1 {
		t.Fatalf("signed %d URLs, want only the authorized one", len(store.signed))
	}

	aid, _ := shared.IDFromString(id)
	repo.rows[aid].SetScan(attachment.ScanInfected, "Eicar-Test-Signature")
	if rec := getDownloadURL(h, id, tenant, user); rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("MALWARE_DETECTED")) {
		t.Fatalf("flagged file: %d %s", rec.Code, rec.Body)
	}

	off, _ := newDirectHandler(t, store, false)
	offID := uploadText(t, off, tenant, user)
	if rec := getDownloadURL(off, offID, tenant, user); rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("DIRECT_DOWNLOAD_UNAVAILABLE")) {
		t.Fatalf("turned off: %d %s", rec.Code, rec.Body)
	}
	local, _ := newDirectHandler(t, storage.NewLocalStorage(t.TempDir()), true)
	localID := uploadText(t, local, tenant, user)
	if rec := getDownloadURL(local, localID, tenant, user); rec.Code != http.StatusConflict {
		t.Fatalf("local storage: %d %s", rec.Code, rec.Body)
	}
}
