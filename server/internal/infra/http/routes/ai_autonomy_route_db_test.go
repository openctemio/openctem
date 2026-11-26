package routes

// Settings > AI > Changes without a person through the real router and table
// (docs/architecture/ai-autonomy.md): read with settings:read; write only an
// owner or administrator with settings:write; pausing and lowering a limit
// are one click, resuming and raising or removing a limit need a recent
// sign-in; audit rows (critical for a loosening); tenant isolation (the
// tenant comes from the token).

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
)

func TestAIAutonomyRoutes_AuthzStepUpAuditIsolation_DB(t *testing.T) {
	h, gate := newUseCaseRouteHarness(t)
	org, other := h.tenant(), h.tenant()
	for _, id := range []string{org, other} {
		id := id
		h.t.Cleanup(func() {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenant_ai_settings WHERE tenant_id = $1`, id)
		})
	}
	admin := h.member(org, "admin")
	reader := h.member(org, "member")
	h.grantCustomRole(&reader, org, "settings:read")
	writer := h.member(org, "member") // settings:write, but not an administrator
	h.grantCustomRole(&writer, org, "settings:read", "settings:write")
	otherAdmin := h.member(other, "admin")
	const path = "/api/v1/organization/settings/ai/autonomy"

	// Defaults until saved.
	body := h.expect(reader, http.MethodGet, path, "", http.StatusOK)
	if !strings.Contains(body, `"paused":false`) || !strings.Contains(body, `"per_hour":100`) || !strings.Contains(body, `"per_day":500`) {
		t.Fatalf("defaults: %s", body)
	}

	// Write: only an owner or administrator with settings:write.
	pause := `{"paused":true,"per_hour":100,"per_day":500}`
	h.expect(reader, http.MethodPut, path, pause, http.StatusForbidden)
	h.expect(writer, http.MethodPut, path, pause, http.StatusForbidden)

	// Validation: both limits must be sent; bounds.
	h.expect(admin, http.MethodPut, path, `{"paused":true}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPut, path, `{"paused":false,"per_hour":-1,"per_day":5}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPut, path, `{"paused":false,"per_hour":1,"per_day":100001}`, http.StatusBadRequest)

	// Pausing and lowering need no recent sign-in.
	gate.set(true)
	resp := h.expect(admin, http.MethodPut, path, `{"paused":true,"per_hour":10,"per_day":50}`, http.StatusOK)
	if !strings.Contains(resp, `"paused":true`) || !strings.Contains(resp, `"per_hour":10`) {
		t.Fatalf("pause: %s", resp)
	}
	// Resuming, raising and removing a limit on a stale sign-in: refused,
	// nothing stored.
	for _, loosen := range []string{
		`{"paused":false,"per_hour":10,"per_day":50}`,
		`{"paused":true,"per_hour":11,"per_day":50}`,
		`{"paused":true,"per_hour":10,"per_day":null}`,
	} {
		resp = h.expect(admin, http.MethodPut, path, loosen, http.StatusForbidden)
		if !strings.Contains(resp, string(middleware.CodeStepUpRequired)) {
			t.Fatalf("stale sign-in %s: %s", loosen, resp)
		}
	}
	body = h.expect(admin, http.MethodGet, path, "", http.StatusOK)
	if !strings.Contains(body, `"paused":true`) || !strings.Contains(body, `"per_day":50`) {
		t.Fatalf("a refused loosening was stored: %s", body)
	}

	// Fresh sign-in: resumed, unlimited per day, audited critical.
	gate.set(false)
	resp = h.expect(admin, http.MethodPut, path, `{"paused":false,"per_hour":10,"per_day":null}`, http.StatusOK)
	if !strings.Contains(resp, `"per_day":null`) || !strings.Contains(resp, `"loosened":["resumed","limit_removed"]`) {
		t.Fatalf("loosening: %s", resp)
	}
	paused := h.auditRows(org, "ai_autonomy.paused")
	resumed := h.auditRows(org, "ai_autonomy.resumed")
	updated := h.auditRows(org, "ai_autonomy.updated")
	if len(paused) != 1 || len(resumed) != 1 || len(updated) != 2 {
		t.Fatalf("audit rows: paused %d resumed %d updated %d", len(paused), len(resumed), len(updated))
	}
	if resumed[0].severity != "critical" || resumed[0].actor != admin.id || updated[1].severity != "critical" || updated[0].severity != "medium" {
		t.Fatalf("audit severities: %+v %+v", resumed, updated)
	}

	// Another organization sees its own defaults and wrote nothing.
	body = h.expect(otherAdmin, http.MethodGet, path, "", http.StatusOK)
	if !strings.Contains(body, `"per_hour":100`) || strings.Contains(body, `"per_day":null`) {
		t.Fatalf("another organization sees this one's settings: %s", body)
	}
	if n := useCaseCount(h, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'ai_autonomy.%'`, other); n != 0 {
		t.Fatal("audit rows written to another organization")
	}
}
