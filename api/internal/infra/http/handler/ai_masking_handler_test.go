package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type stubMaskingStore struct {
	gotTID     string
	gotUpdate  tenantai.MaskingUpdate
	gotPreview tenantai.PreviewInput
	preview    tenantai.MaskingPreview
	err        error
}

func (s *stubMaskingStore) GetMasking(_ context.Context, tid string) (tenantai.MaskingView, error) {
	s.gotTID = tid
	return tenantai.MaskingView{Classes: []tenantai.MaskingClass{{Class: "hosts", Masked: true}}}, s.err
}

func (s *stubMaskingStore) SaveMasking(_ context.Context, tid string, in tenantai.MaskingUpdate, _ auditapp.AuditContext) (tenantai.MaskingView, error) {
	s.gotTID, s.gotUpdate = tid, in
	return tenantai.MaskingView{}, s.err
}

func (s *stubMaskingStore) PreviewMasking(_ context.Context, in tenantai.PreviewInput, _ auditapp.AuditContext) (tenantai.MaskingPreview, error) {
	s.gotPreview = in
	return s.preview, s.err
}

const maskTenant = "11111111-1111-7111-8111-111111111111"

func maskReq(method, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/organization/settings/ai/masking", strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, maskTenant))
}

// The tenant comes from the context only; the body cannot name another one.
func TestAIMaskingHandler_TenantFromContext(t *testing.T) {
	st := &stubMaskingStore{}
	h := NewAIMaskingHandler(st, validator.New(), logger.NewNop())
	rec := httptest.NewRecorder()
	h.Update(rec, maskReq(http.MethodPut, `{"tenant_id":"22222222-2222-7222-8222-222222222222","off":["ips"],"terms":["Acme"]}`))
	if rec.Code != http.StatusOK || st.gotTID != maskTenant || len(st.gotUpdate.Off) != 1 {
		t.Fatalf("status %d tenant %q update %+v", rec.Code, st.gotTID, st.gotUpdate)
	}
	rec = httptest.NewRecorder()
	h.Get(rec, maskReq(http.MethodGet, ""))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"terms":[]`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
}

func TestAIMaskingHandler_PreviewNeverReturnsValues(t *testing.T) {
	st := &stubMaskingStore{preview: tenantai.MaskingPreview{Text: "host DOMAIN_ABC2DE",
		Placeholders: []aimask.Placeholder{{Token: "DOMAIN_ABC2DE", Class: aimask.ClassDomain}}}}
	h := NewAIMaskingHandler(st, validator.New(), logger.NewNop())
	rec := httptest.NewRecorder()
	h.Preview(rec, maskReq(http.MethodPost, `{"finding_id":"33333333-3333-7333-8333-333333333333"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"value"`) {
		t.Fatalf("preview must never carry values: %s", rec.Body)
	}
	if st.gotPreview.TenantID != maskTenant {
		t.Fatalf("tenant %q", st.gotPreview.TenantID)
	}
}

func TestAIMaskingHandler_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		err  error
		want int
	}{
		"bad id":       {`{"finding_id":"x"}`, nil, http.StatusBadRequest},
		"bad class":    {`{"finding_id":"33333333-3333-7333-8333-333333333333","data_class":"tenant_only"}`, nil, http.StatusBadRequest},
		"not found":    {`{"finding_id":"33333333-3333-7333-8333-333333333333"}`, shared.ErrNotFound, http.StatusNotFound},
		"policy":       {`{"finding_id":"33333333-3333-7333-8333-333333333333"}`, aipolicy.ErrRestricted, http.StatusForbidden},
		"nothing left": {`{"finding_id":"33333333-3333-7333-8333-333333333333"}`, aibundle.ErrEmpty, http.StatusUnprocessableEntity},
	} {
		h := NewAIMaskingHandler(&stubMaskingStore{err: tc.err}, validator.New(), logger.NewNop())
		rec := httptest.NewRecorder()
		h.Preview(rec, maskReq(http.MethodPost, tc.body))
		if rec.Code != tc.want {
			t.Errorf("%s: status %d want %d (%s)", name, rec.Code, tc.want, rec.Body)
		}
	}
}
