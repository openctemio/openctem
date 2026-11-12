package handler

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An unknown context type would skip every context check, so upload, list and
// link refuse it instead of storing or serving an unchecked context.
func TestAttachmentContextType_UnknownRefused(t *testing.T) {
	h := newUploadHandler(t, 0)
	tenant, user := shared.NewID().String(), shared.NewID().String()
	ctxID := shared.NewID().String()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("context_type", "foo")
	_ = mw.WriteField("context_id", ctxID)
	fw, _ := mw.CreateFormFile("file", "a.txt")
	_, _ = fw.Write([]byte("hello"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/attachments", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.Upload(rec, asMember(r, tenant, user))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("upload with context_type=foo = %d, want 400", rec.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/v1/attachments?context_type=foo&context_id="+ctxID, nil)
	rec = httptest.NewRecorder()
	h.List(rec, asMember(r, tenant, user))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("list with context_type=foo = %d, want 400", rec.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/v1/attachments/link",
		strings.NewReader(`{"attachment_ids":["`+shared.NewID().String()+`"],"context_type":"foo","context_id":"`+ctxID+`"}`))
	rec = httptest.NewRecorder()
	h.LinkToContext(rec, asMember(r, tenant, user))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("link with context_type=foo = %d, want 400", rec.Code)
	}
}
