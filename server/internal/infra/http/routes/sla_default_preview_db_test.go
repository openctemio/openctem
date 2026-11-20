package routes

// "Make default" preview against a migrated database: counts the open findings
// the default governs, changes nothing, and stays inside the caller's tenant.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	slaapp "github.com/openctemio/openctem/server/internal/app/sla"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

func (h *grbHarness) slaPolicy(tenant shared.ID, name string, def, active bool, asset string, crit, high, med, low, info int) string {
	h.t.Helper()
	id := uuid.NewString()
	var a any
	if asset != "" {
		a = asset
	}
	h.exec(`INSERT INTO sla_policies (id, tenant_id, asset_id, name, is_default, is_active, critical_days, high_days, medium_days, low_days, info_days, p0_days, p1_days, p2_days, p3_days)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 2, 5, 15, 30)`,
		id, tenant.String(), a, name, def, active, crit, high, med, low, info)
	return id
}

func (h *grbHarness) slaFinding(tenant shared.ID, asset, sev, status, practice string, detectedDaysAgo int, deadlineInDays *int) {
	h.t.Helper()
	id := uuid.NewString()
	var a any
	if asset != "" {
		a = asset
	}
	var dl any
	if deadlineInDays != nil {
		dl = *deadlineInDays
	}
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, practice, first_detected_at, sla_deadline)
		VALUES ($1::uuid, $2, $3, 'sast', 'x', 'm', $4, $1::text, $5, $6, now() - make_interval(days => $7::int),
		        CASE WHEN $8::int IS NULL THEN NULL ELSE now() + make_interval(days => $8::int) END)`,
		id, tenant.String(), a, sev, status, practice, detectedDaysAgo, dl)
}

func TestSLADefaultPreview_DB(t *testing.T) {
	h := newGRBHarness(t)
	log := logger.NewNop()
	repo := postgres.NewSLAPolicyRepository(&postgres.DB{DB: h.db})
	hd := handler.NewSLAHandler(slaapp.NewService(repo, log), validator.New(), log)

	// Current default: loose windows. Candidate: tight critical and high, loose low, no info SLA.
	cur := h.slaPolicy(h.tenant, "current", true, true, "", 30, 60, 90, 120, 0)
	cand := h.slaPolicy(h.tenant, "candidate", false, true, "", 7, 14, 30, 200, 0)
	inactive := h.slaPolicy(h.tenant, "inactive", false, false, "", 7, 14, 30, 60, 0)

	ten := func(n int) *int { return &n }
	asset := uuid.NewString()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'a', 'domain', 'public', 'high')`, asset, h.tenant.String())
	ownAssetPolicy := h.slaPolicy(h.tenant, "asset own", false, true, asset, 3, 3, 3, 3, 3)
	_ = ownAssetPolicy

	h.slaFinding(h.tenant, "", "critical", "new", "other", 20, ten(10))  // 7d window: earlier and overdue
	h.slaFinding(h.tenant, "", "low", "new", "other", 10, ten(50))       // 200d window: later
	h.slaFinding(h.tenant, "", "info", "new", "other", 5, nil)           // no SLA: governed, unchanged
	h.slaFinding(h.tenant, "", "critical", "new", "other", 30, nil)      // no deadline yet: overdue under the candidate
	h.slaFinding(h.tenant, asset, "high", "new", "other", 40, ten(5))    // own asset policy: not governed
	h.slaFinding(h.tenant, "", "critical", "resolved", "other", 40, nil) // closed
	h.slaFinding(h.tenant, "", "high", "new", "compliance", 40, ten(5))  // compliance practice
	h.slaFinding(h.other, "", "critical", "new", "other", 40, ten(1))    // another organization

	call := func(tenant shared.ID, perms []string, policy string) (int, map[string]any) {
		called := false
		gate := middleware.Require(permission.SLAWrite)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			hd.PreviewDefault(w, r)
		}))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/sla-policies/"+policy+"/default-preview", nil)
		req.SetPathValue("id", policy)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code == http.StatusForbidden && called {
			t.Error("handler ran for a refused caller")
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	write := []string{string(permission.SLAWrite)}

	code, got := call(h.tenant, write, cand)
	if code != http.StatusOK {
		t.Fatalf("preview = %d %v", code, got)
	}
	want := map[string]float64{"governed": 4, "earlier": 1, "become_overdue": 2, "later": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	if got["already_default"] != false {
		t.Errorf("already_default = %v", got["already_default"])
	}

	// Read-only: nothing was rewritten.
	var isDef bool
	_ = h.db.QueryRowContext(context.Background(), `SELECT is_default FROM sla_policies WHERE id = $1`, cand).Scan(&isDef)
	if isDef {
		t.Error("the preview made the policy the default")
	}
	var moved int
	_ = h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND sla_deadline IS NOT NULL AND sla_deadline < now() + interval '2 days' AND source = 'sast' AND severity = 'critical'`, h.tenant.String()).Scan(&moved)
	if moved != 0 {
		t.Errorf("a stored deadline moved (%d)", moved)
	}

	// The current default, an inactive policy, another organization's policy.
	if _, got := call(h.tenant, write, cur); got["already_default"] != true || got["governed"] != float64(0) {
		t.Errorf("current default preview = %v", got)
	}
	if code, _ := call(h.tenant, write, inactive); code != http.StatusBadRequest {
		t.Errorf("inactive policy = %d, want 400", code)
	}
	if code, _ := call(h.other, write, cand); code != http.StatusNotFound {
		t.Errorf("another organization's policy = %d, want 404", code)
	}
	// The other organization's preview of its own policy counts only its findings.
	otherPolicy := h.slaPolicy(h.other, "other cand", false, true, "", 1, 1, 1, 1, 0)
	if code, got := call(h.other, write, otherPolicy); code != http.StatusOK || got["governed"] != float64(1) {
		t.Errorf("other organization preview = %d %v", code, got)
	}

	// Without sla:write (reading policies is not enough): refused.
	if code, _ := call(h.tenant, []string{string(permission.SLARead)}, cand); code != http.StatusForbidden {
		t.Errorf("sla:read only = %d, want 403", code)
	}
}
