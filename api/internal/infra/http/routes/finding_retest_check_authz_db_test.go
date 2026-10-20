package routes

// A finding's retest check over the real route registration
// (docs/architecture/finding-retest-checks.md): the permission gates, the
// finding data scope, tenant isolation. DB-gated (rtHarness).

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const rcAssertion = `{"kind":"http_assertion","assertion":{"method":"GET","path":"/admin","matchers":[{"type":"status","status":[200]}]}}`

func (h *rtHarness) doBody(user shared.ID, perms []permission.Permission, method, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.String())
	}
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Perms", strings.Join(names, ","))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestFindingRetestCheckAuthzDB(t *testing.T) {
	h := newRetestAuthzHarness(t)
	read := []permission.Permission{permission.FindingsRead}
	write := []permission.Permission{permission.FindingsRead, permission.FindingsRetestChecksWrite}
	path := func(f shared.ID, suffix string) string {
		return "/api/v1/findings/" + f.String() + "/retest-check" + suffix
	}

	// Reading needs findings:read; a finding without a check answers null.
	if code, body := h.do(h.writer, read, http.MethodGet, path(h.findingA1, "/")); code != http.StatusOK || !strings.Contains(body, `"check":null`) {
		t.Fatalf("get without check: %d %s", code, body)
	}
	// Writing needs findings:retest_checks:write.
	for _, c := range []struct{ method, suffix string }{
		{http.MethodPut, "/"}, {http.MethodPost, "/validate"}, {http.MethodDelete, "/"},
	} {
		if code, body := h.doBody(h.writer, read, c.method, path(h.findingA1, c.suffix), rcAssertion); code != http.StatusForbidden {
			t.Errorf("%s %s without the permission: %d %s", c.method, c.suffix, code, body)
		}
	}
	// Validate reports problems without saving.
	if code, body := h.doBody(h.writer, write, http.MethodPost, path(h.findingA1, "/validate"),
		`{"kind":"http_assertion","assertion":{"method":"GET","path":"//evil.example/","matchers":[{"type":"status","status":[200]}]}}`); code != http.StatusOK || !strings.Contains(body, `"valid":false`) {
		t.Fatalf("validate off-target: %d %s", code, body)
	}
	// Save, then read it back.
	if code, body := h.doBody(h.writer, write, http.MethodPut, path(h.findingA1, "/"), rcAssertion); code != http.StatusOK ||
		!strings.Contains(body, `"kind":"http_assertion"`) || !strings.Contains(body, `"tier":"T0"`) || !strings.Contains(body, `"calibrated":false`) {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body := h.do(h.scoped, read, http.MethodGet, path(h.findingA1, "/")); code != http.StatusOK || !strings.Contains(body, "{{BaseURL}}/admin") {
		t.Fatalf("get in scope: %d %s", code, body)
	}
	// An invalid check is refused and changes nothing.
	if code, body := h.doBody(h.writer, write, http.MethodPut, path(h.findingA1, "/"), `{"kind":"nuclei","content":"id: [broken"}`); code != http.StatusBadRequest {
		t.Fatalf("put broken: %d %s", code, body)
	}
	// Unknown fields are refused (no smuggled target).
	if code, _ := h.doBody(h.writer, write, http.MethodPut, path(h.findingA1, "/"), `{"kind":"nuclei","content":"x","target":"https://evil.example"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}

	// SECURITY: out of the caller's data scope and other tenants' findings are 404.
	if code, _ := h.do(h.scoped, read, http.MethodGet, path(h.findingA2, "/")); code != http.StatusNotFound {
		t.Fatalf("out of scope get: %d", code)
	}
	if code, _ := h.doBody(h.scoped, write, http.MethodPut, path(h.findingA2, "/"), rcAssertion); code != http.StatusNotFound {
		t.Fatalf("out of scope put: %d", code)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if code, _ := h.doBody(h.writer, write, m, path(h.findingB, "/"), rcAssertion); code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s: %d", m, code)
		}
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM finding_retest_checks WHERE finding_id IN ($1, $2)`, h.findingA2.String(), h.findingB.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("checks written out of scope: %d %v", n, err)
	}

	// Approving needs scope:approve.
	if code, _ := h.doBody(h.writer, write, http.MethodPost, path(h.findingA1, "/approve"), ""); code != http.StatusForbidden {
		t.Fatalf("approve without scope:approve: %d", code)
	}
	// Remove, then it is gone.
	if code, body := h.doBody(h.writer, write, http.MethodDelete, path(h.findingA1, "/"), ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, body)
	}
	if code, _ := h.doBody(h.writer, write, http.MethodDelete, path(h.findingA1, "/"), ""); code != http.StatusNotFound {
		t.Fatalf("second delete: %d", code)
	}
}
