package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func postIdPMetadata(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewSAMLHandler(auth.NewSAMLService(nil, nil, nil, logger.NewNop()), CookieConfig{}, "", logger.NewNop())
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/tenants/x/sso/saml/idp-metadata", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, "11111111-1111-7111-8111-111111111111"))
	w := httptest.NewRecorder()
	h.ImportIdPMetadata(w, r)
	return w
}

// A refused document answers 422 with the registered code and a reason the
// console translates; the document's own text never comes back.
func TestImportIdPMetadataHandler_RefusalCarriesReasonOnly(t *testing.T) {
	doc := `<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&secret;"/>`
	payload, _ := json.Marshal(map[string]string{"metadata_xml": doc})
	w := postIdPMetadata(t, string(payload))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	var got struct {
		Code    string         `json:"code"`
		Details map[string]any `json:"details"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Code != "SAML_METADATA_INVALID" || got.Details["reason"] != auth.SAMLMetadataReasonDoctype {
		t.Fatalf("body = %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "passwd") {
		t.Fatal("the response echoes the document")
	}
}

func TestImportIdPMetadataHandler_BlockedURL(t *testing.T) {
	w := postIdPMetadata(t, `{"metadata_url":"https://169.254.169.254/latest/meta-data"}`)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), auth.SAMLMetadataReasonURLBlocked) {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
}

func TestImportIdPMetadataHandler_BodyTooLarge(t *testing.T) {
	big := `{"metadata_xml":"` + strings.Repeat("a", maxSAMLIdPMetadataRequest+10) + `"}`
	if w := postIdPMetadata(t, big); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// The SP metadata download is built on APP_URL only: through the console the
// request's host is the console's, not the address the IdP must post to.
func TestSPMetadataHandler_RequiresPublicURL(t *testing.T) {
	h := NewSAMLHandler(auth.NewSAMLService(nil, nil, nil, logger.NewNop()), CookieConfig{}, "", logger.NewNop())
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/tenants/x/sso/saml/sp-metadata", nil)
	r.Host = "console.example.com"
	r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, "11111111-1111-7111-8111-111111111111"))
	w := httptest.NewRecorder()
	h.SPMetadata(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "SAML_PUBLIC_URL_UNSET") {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
}

// A fetched URL shows one reason for "the host did not answer" and "it
// answered something that is not metadata", so the console cannot probe
// internal hosts; a pasted document keeps its own reason.
func TestSAMLMetadataRefusalForResponse(t *testing.T) {
	for _, reason := range []string{auth.SAMLMetadataReasonUnreachable, auth.SAMLMetadataReasonMalformed, auth.SAMLMetadataReasonNotMetadata} {
		code, shown := samlMetadataRefusalForResponse(reason, true)
		if code != apierror.CodeSAMLMetadataUnreachable || shown != auth.SAMLMetadataReasonUnreachable {
			t.Fatalf("url %s: got %s %s", reason, code, shown)
		}
	}
	if code, shown := samlMetadataRefusalForResponse(auth.SAMLMetadataReasonMalformed, false); code != apierror.CodeSAMLMetadataInvalid || shown != auth.SAMLMetadataReasonMalformed {
		t.Fatalf("a pasted document keeps its reason, got %s %s", code, shown)
	}
	if _, shown := samlMetadataRefusalForResponse(auth.SAMLMetadataReasonNoSSOURL, true); shown != auth.SAMLMetadataReasonNoSSOURL {
		t.Fatalf("a structural reason is kept, got %s", shown)
	}
}
