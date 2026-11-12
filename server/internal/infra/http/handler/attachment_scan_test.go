package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func withID(r *http.Request, id string) *http.Request {
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func pngWithText(t *testing.T, text string) []byte {
	t.Helper()
	p := validPNG(t)
	chunk := make([]byte, 8, 12+len(text))
	binary.BigEndian.PutUint32(chunk, uint32(len(text)))
	copy(chunk[4:], "tEXt")
	chunk = append(chunk, text...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(append([]byte("tEXt"), text...)))
	return append(append(append([]byte{}, p[:33]...), chunk...), p[33:]...)
}

// An uploaded image is stored without its metadata; the response and the
// stored bytes agree.
func TestAttachmentUpload_ImageMetadataRemoved(t *testing.T) {
	h := newUploadHandler(t, 0)
	tenant, user := shared.NewID().String(), shared.NewID().String()
	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "shot.png", "image/png", pngWithText(t, "GPS\x0052.37N 4.90E")), tenant, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID   string `json:"id"`
		Size int64  `json:"size"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	rec = httptest.NewRecorder()
	h.Download(rec, withID(asMember(httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+out.ID, nil), tenant, user), out.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("download: %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if bytes.Contains(body, []byte("52.37N")) || !bytes.Equal(body, validPNG(t)) || int64(len(body)) != out.Size {
		t.Fatalf("stored image still carries its metadata (%d bytes, recorded %d)", len(body), out.Size)
	}
}

// A file the scanner flagged answers 409 MALWARE_DETECTED until the caller
// confirms; then it downloads as an attachment, never inline, never cached.
// Another organization still gets 404.
func TestAttachmentDownload_InfectedNeedsConfirmation(t *testing.T) {
	log := logger.New(logger.Config{Level: "error", Format: "text"})
	repo := &memAttRepo{rows: map[shared.ID]*attachment.Attachment{}}
	svc := integration.NewAttachmentService(repo, storage.NewLocalStorage(t.TempDir()), log)
	h := NewAttachmentHandler(svc, log)
	tenant, user := shared.NewID().String(), shared.NewID().String()

	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "shot.png", "image/png", validPNG(t)), tenant, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id, _ := shared.IDFromString(out.ID)
	repo.rows[id].SetScan(attachment.ScanInfected, "Eicar-Test-Signature")

	get := func(tid, query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Download(rec, withID(asMember(httptest.NewRequest(http.MethodGet, "/api/v1/attachments/"+out.ID+query, nil), tid, user), out.ID))
		return rec
	}
	if rec := get(tenant, ""); rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("MALWARE_DETECTED")) {
		t.Fatalf("unconfirmed: %d %s", rec.Code, rec.Body)
	}
	if rec := get(tenant, "?confirm=yes"); rec.Code != http.StatusConflict {
		t.Fatalf("wrong confirmation: %d", rec.Code)
	}
	rec = get(tenant, "?confirm=malware")
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed: %d %s", rec.Code, rec.Body)
	}
	if cd := rec.Header().Get("Content-Disposition"); len(cd) < 10 || cd[:10] != "attachment" {
		t.Errorf("flagged image served %q, want attachment", cd)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
	if rec := get(shared.NewID().String(), "?confirm=malware"); rec.Code != http.StatusNotFound {
		t.Fatalf("other organization: %d, want 404", rec.Code)
	}
}

// An image declaring more pixels than the limit is refused with
// IMAGE_TOO_LARGE before anything is stored.
func TestAttachmentUpload_PixelLimit(t *testing.T) {
	h := newUploadHandler(t, 0)
	p := validPNG(t)
	ihdr := append([]byte{}, p[16:29]...)
	binary.BigEndian.PutUint32(ihdr[0:], 30000)
	binary.BigEndian.PutUint32(ihdr[4:], 30000)
	chunk := append([]byte{0, 0, 0, 13, 'I', 'H', 'D', 'R'}, ihdr...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(append([]byte("IHDR"), ihdr...)))
	copy(p[8:33], chunk)
	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(uploadReq(t, "bomb.png", "image/png", p), shared.NewID().String(), shared.NewID().String()))
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("IMAGE_TOO_LARGE")) {
		t.Fatalf("bomb: %d %s", rec.Code, rec.Body)
	}
}
