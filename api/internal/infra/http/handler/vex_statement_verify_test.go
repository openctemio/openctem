package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vexapp "github.com/openctemio/openctem/api/internal/app/vex"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A caller with findings:approve but not findings:verify cannot write a
// fixed statement: the handler passes the missing permission to the service,
// which refuses before it reads or writes anything (the service has no
// repository here, so any access would panic).
func TestVEXStatementHandler_FixedNeedsVerify(t *testing.T) {
	h := NewVEXStatementHandler(vexapp.NewService(nil, nil, nil, nil), logger.NewNop())
	req := func(path, body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		ctx := context.WithValue(r.Context(), middleware.TenantIDKey, shared.NewID().String())
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, []string{"findings:approve"})
		return r.WithContext(ctx)
	}

	w := httptest.NewRecorder()
	h.Create(w, req("/api/v1/vex-statements", `{"vuln_id":"CVE-2021-23337","product_id":"`+shared.NewID().String()+`","status":"fixed"}`))
	if w.Code != http.StatusForbidden {
		t.Errorf("create fixed without findings:verify: %d, want 403 (%s)", w.Code, w.Body.String())
	}

	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1","author":"a","timestamp":"2026-10-01T00:00:00Z","version":1,"statements":[
	 {"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash@4.17.20"}],"status":"fixed"}]}`
	w = httptest.NewRecorder()
	h.Import(w, req("/api/v1/vex-statements/import", doc))
	if w.Code != http.StatusForbidden {
		t.Errorf("import with a fixed statement without findings:verify: %d, want 403 (%s)", w.Code, w.Body.String())
	}
}
