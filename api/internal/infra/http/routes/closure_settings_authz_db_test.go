package routes

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The closing mode lives under the token singleton: the tenant comes from the
// credential, only an owner/admin may read or change it, and turning critical
// auto-close on is refused to anyone but the organization owner.
func TestClosureSettingsAuthz_AdminOnlyOwnerForCritical(t *testing.T) {
	h := newRetestAuthzHarness(t)
	call := func(method, body string, admin bool) (int, string) {
		url := h.srv.URL + "/api/v1/organization/settings/closure"
		if method == http.MethodDelete {
			url += "/pending"
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", h.verifier.String())
		req.Header.Set("X-Test-Perms", "findings:read,findings:verify")
		if admin {
			req.Header.Set("X-Test-Admin", "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if status, body := call(http.MethodGet, "", false); status != http.StatusForbidden {
		t.Fatalf("member GET closure = %d, want 403 (%s)", status, body)
	}
	if status, body := call(http.MethodPut, `{"mode":"off"}`, false); status != http.StatusForbidden {
		t.Fatalf("member PUT closure = %d, want 403 (%s)", status, body)
	}
	if status, body := call(http.MethodPut, `{"mode":"sometimes"}`, true); status != http.StatusBadRequest {
		t.Fatalf("bad mode = %d, want 400 (%s)", status, body)
	}
	// Tightening (unset = review -> off) is immediate.
	if status, body := call(http.MethodPut, `{"mode":"off"}`, true); status != http.StatusOK || !strings.Contains(body, `"mode":"off"`) {
		t.Fatalf("admin PUT closure = %d (%s)", status, body)
	}
	// The caller is not the owner: critical auto-close is refused.
	if status, body := call(http.MethodPut, `{"mode":"auto","critical_auto_close":true}`, true); status != http.StatusForbidden {
		t.Fatalf("non-owner critical auto-close = %d, want 403 (%s)", status, body)
	}
	if status, body := call(http.MethodGet, "", true); status != http.StatusOK || !strings.Contains(body, `"mode":"off"`) {
		t.Fatalf("admin GET closure = %d (%s)", status, body)
	}
	// Canceling a waiting loosening is for owners and administrators too.
	if status, body := call(http.MethodDelete, "", false); status != http.StatusForbidden {
		t.Fatalf("member cancel = %d, want 403 (%s)", status, body)
	}
	if status, body := call(http.MethodDelete, "", true); status != http.StatusOK || !strings.Contains(body, `"mode":"off"`) {
		t.Fatalf("admin cancel = %d (%s)", status, body)
	}
	var modeA, modeB sql.NullString
	_ = h.db.QueryRow(`SELECT settings->'closure'->>'mode' FROM tenants WHERE id = $1`, h.tenantA.String()).Scan(&modeA)
	_ = h.db.QueryRow(`SELECT settings->'closure'->>'mode' FROM tenants WHERE id = $1`, h.tenantB.String()).Scan(&modeB)
	if modeA.String != "off" || modeB.Valid {
		t.Fatalf("settings written to the wrong organization: A=%q B=%q", modeA.String, modeB.String)
	}
}
