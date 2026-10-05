package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fixedSCIMToken struct{ tok *scimtoken.ScimToken }

func (f fixedSCIMToken) Authenticate(_ context.Context, plaintext string) (*scimtoken.ScimToken, error) {
	if plaintext != "good" {
		return nil, scimtoken.ErrNotFound
	}
	return f.tok, nil
}

// SCIMAuth binds the tenant and records the token as the audit actor, so a
// role change made by the identity provider names the token (23b S-H1).
func TestSCIMAuth_RecordsTokenAsAuditActor(t *testing.T) {
	tenantID := shared.NewID()
	tok := scimtoken.New(shared.NewID(), tenantID, "okta", "hash", "scim_abc")
	var gotTenant shared.ID
	var gotID, gotPrefix string
	var ok bool
	h := SCIMAuth(fixedSCIMToken{tok})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotTenant, _ = SCIMTenantID(r.Context())
		gotID, gotPrefix, ok = auditapp.SCIMTokenActor(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer good")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if gotTenant != tenantID || !ok || gotID != tok.ID().String() || gotPrefix != "scim_abc" {
		t.Fatalf("tenant %s actor %q/%q ok=%v, want tenant %s and token %s/scim_abc", gotTenant, gotID, gotPrefix, ok, tenantID, tok.ID())
	}

	rec := httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	bad.Header.Set("Authorization", "Bearer nope")
	h.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", rec.Code)
	}
}
