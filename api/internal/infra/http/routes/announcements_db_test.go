package routes

// Platform announcements over the real route registration:
//
//   - a readonly administrator lists them but cannot publish or end one;
//   - an operations administrator publishes one (reason required, one plain
//     line, a bounded window) and every signed-in organization user sees it
//     at GET /api/v1/announcements; ending it takes it down at once.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newAnnouncementsHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		h.Announcement = handler.NewAnnouncementHandler(postgres.NewPlatformAnnouncementRepository(db), logger.NewNop())
		h.AdminAuditMiddleware = middleware.NewAuditMiddleware(postgres.NewAuditLogRepository(db), logger.NewNop())
	})
}

func activeAnnouncements(t *testing.T, h *chainHarness, token string) []handler.AnnouncementResponse {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/announcements", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("active announcements: %d %s", resp.StatusCode, b)
	}
	var out handler.AnnouncementListResponse
	_ = json.Unmarshal(b, &out)
	return out.Data
}

func TestAnnouncements(t *testing.T) {
	h := newAnnouncementsHarness(t)
	org := h.organization(0)
	member := h.tenantToken(org, "viewer")

	// Anonymous callers do not read announcements.
	anon, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/announcements", nil)
	resp, err := http.DefaultClient.Do(anon)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d, want 401", resp.StatusCode)
	}

	msg := "Maintenance tonight 22:00-23:00 UTC " + time.Now().Format("150405.000000")
	body := map[string]any{
		"message": msg, "severity": "maintenance",
		"ends_at": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		"reason":  "Planned database upgrade, change 812",
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM platform_announcements WHERE message = $1`, msg)
	})

	t.Run("readonly lists but cannot publish", func(t *testing.T) {
		ro := newAnnouncementsHarness(t).newAdmin(admin.AdminRoleReadonly)
		ro.verify()
		if code, _ := ro.do(http.MethodGet, "/api/v1/admin/announcements", nil, false); code != http.StatusOK {
			t.Fatalf("list: %d", code)
		}
		if code, _ := ro.do(http.MethodPost, "/api/v1/admin/announcements", body, true); code != http.StatusForbidden {
			t.Fatalf("publish as readonly: %d, want 403", code)
		}
	})

	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()

	t.Run("bad input is refused", func(t *testing.T) {
		bad := []map[string]any{
			{"message": "line one\nline two", "severity": "info", "ends_at": body["ends_at"], "reason": body["reason"]},
			{"message": msg, "severity": "critical", "ends_at": body["ends_at"], "reason": body["reason"]},
			{"message": msg, "severity": "info", "ends_at": body["ends_at"]},
			{"message": msg, "severity": "info", "ends_at": time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339), "reason": body["reason"]},
			{"message": strings.Repeat("x", 501), "severity": "info", "ends_at": body["ends_at"], "reason": body["reason"]},
		}
		for i, b := range bad {
			if code, out := ops.do(http.MethodPost, "/api/v1/admin/announcements", b, true); code != http.StatusBadRequest {
				t.Fatalf("case %d: %d %s, want 400", i, code, out)
			}
		}
	})

	code, out := ops.do(http.MethodPost, "/api/v1/admin/announcements", body, true)
	if code != http.StatusCreated {
		t.Fatalf("publish: %d %s", code, out)
	}
	var created handler.AdminAnnouncementResponse
	_ = json.Unmarshal([]byte(out), &created)
	if created.State != "active" {
		t.Fatalf("created = %+v", created)
	}

	found := false
	for _, a := range activeAnnouncements(t, h, member) {
		if a.ID == created.ID && a.Message == msg && a.Severity == "maintenance" {
			found = true
		}
	}
	if !found {
		t.Fatal("an organization member does not see the active announcement")
	}

	if code, _ := ops.do(http.MethodPost, "/api/v1/admin/announcements/"+created.ID+"/cancel",
		map[string]string{"reason": "Upgrade finished early"}, true); code != http.StatusNoContent {
		t.Fatalf("cancel: %d", code)
	}
	for _, a := range activeAnnouncements(t, h, member) {
		if a.ID == created.ID {
			t.Fatal("an ended announcement is still shown")
		}
	}
	if code, _ := ops.do(http.MethodPost, "/api/v1/admin/announcements/"+created.ID+"/cancel",
		map[string]string{"reason": "Upgrade finished early"}, true); code != http.StatusConflict {
		t.Fatalf("second cancel: %d, want 409", code)
	}
}
