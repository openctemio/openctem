package handler

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/internal/app/platformai"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const aiPath = "/api/v1/admin/settings/ai"

func aiHandler(t *testing.T, gate *fakeGate) (*AdminPlatformSettingsHandler, *cst.Repo) {
	t.Helper()
	repo := cst.NewRepo()
	svc := platformai.NewService(repo, cst.Cipher(t), cst.Recorder(&cst.Audit{}, &cst.Notifier{}), false, "claude", "env-model", nil)
	h := NewAdminPlatformSettingsHandler(nil, logger.NewNop()).WithApprovals(gate)
	h.AI = svc
	return h, repo
}

func aiPut(t *testing.T, h *AdminPlatformSettingsHandler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.UpdatePlatformAI(rec, superAdminRequest(t, http.MethodPut, aiPath, body))
	return rec
}

// The destination of platform AI (provider, server address, private switch,
// key) is changed by one super admin and approved by another; everything
// else stays one-person.
func TestUpdatePlatformAIDestinationNeedsSecondApproval(t *testing.T) {
	const key1, key2 = "sk-ant-first-key-0123456789", "sk-ant-second-key-9876543210"
	on := func(model, key string, version int) string {
		k := ""
		if key != "" {
			k = `,"api_key":"` + key + `"`
		}
		return `{"enabled":true,"provider":"claude","model":"` + model + `","reason":"change"` + k + `,"version":` + strconv.Itoa(version) + `}`
	}
	needApproval := &admin.ApprovalRequiredError{Action: admin.ApprovalPlatformAIDestination}

	t.Run("first enable: 428 and nothing is saved", func(t *testing.T) {
		gate := &fakeGate{err: needApproval}
		h, repo := aiHandler(t, gate)
		rec := aiPut(t, h, on("m1", key1, 0))
		if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "SECOND_APPROVAL_REQUIRED") {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if repo.Raw(platformai.SettingKey) != "" {
			t.Fatal("nothing may be saved without the approval")
		}
		if len(gate.calls) != 1 || !strings.HasPrefix(gate.calls[0], "platform_ai.destination ") {
			t.Fatalf("gate calls %v", gate.calls)
		}
		target := strings.TrimPrefix(gate.calls[0], "platform_ai.destination ")
		if !admin.ApprovalPlatformAIDestination.ValidTarget(target) || strings.Contains(target, key1) {
			t.Fatalf("target %q", target)
		}
	})

	t.Run("approved first enable saves; model change, then key swap and off", func(t *testing.T) {
		gate := &fakeGate{}
		h, _ := aiHandler(t, gate)
		if rec := aiPut(t, h, on("m1", key1, 0)); rec.Code != http.StatusOK {
			t.Fatalf("first enable %d %s", rec.Code, rec.Body.String())
		}
		if len(gate.calls) != 1 {
			t.Fatalf("calls %v", gate.calls)
		}
		// Model change with the stored key: one-person.
		if rec := aiPut(t, h, on("m2", "", 1)); rec.Code != http.StatusOK || len(gate.calls) != 1 {
			t.Fatalf("model change %d calls %v", rec.Code, gate.calls)
		}
		// Key swap: needs the gate again, and a refusal saves nothing.
		gate.err = needApproval
		if rec := aiPut(t, h, on("m2", key2, 2)); rec.Code != http.StatusPreconditionRequired || len(gate.calls) != 2 {
			t.Fatalf("key swap %d calls %v", rec.Code, gate.calls)
		}
		// Turning off (the key removed with it) never asks, even while the gate refuses.
		off := `{"enabled":false,"provider":"claude","model":"m2","reason":"incident","api_key":"","version":2}`
		if rec := aiPut(t, h, off); rec.Code != http.StatusOK || len(gate.calls) != 2 {
			t.Fatalf("turn off %d calls %v", rec.Code, gate.calls)
		}
	})

	t.Run("a failed save hands the approval back", func(t *testing.T) {
		gate := &fakeGate{}
		h, _ := aiHandler(t, gate)
		// Stale version: the approval was spent and must be released.
		if rec := aiPut(t, h, on("m1", key1, 7)); rec.Code != http.StatusConflict || gate.released != 1 {
			t.Fatalf("status %d released %d", rec.Code, gate.released)
		}
	})
}
