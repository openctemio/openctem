package routes

// Platform content pack writes over the real console routes (RFC-061): a
// super admin with a reason and a fresh authenticator code; readonly and ops
// admins refused; the admin audit row carries the reason.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// contentPackHarness is the console with the platform pack routes and one
// pack to act on. Each harness has its own console sign-in rate limiter
// (5 a minute), so a test signs in at most two administrators.
func contentPackHarness(t *testing.T) (*chainHarness, *contentpackapp.PlatformService, *contentpack.PlatformPack) {
	t.Helper()
	var svc *contentpackapp.PlatformService
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		signer, _ := contentpack.NewSigner(bytes.Repeat([]byte{6}, 32))
		svc = contentpackapp.NewPlatformService(postgres.NewPlatformContentPackRepository(db), storage.NewLocalStorage(t.TempDir()), signer, log)
		hs.PlatformContentPack = handler.NewPlatformContentPackHandler(svc, console, postgres.NewAuditLogRepository(db), log)
	})

	// A pack to act on, ingested directly.
	name := "words-" + strings.ReplaceAll(shared.NewID().String()[24:], "-", "")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	data := name + "\nadmin\n"
	_ = tw.WriteHeader(&tar.Header{Name: "w.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))})
	_, _ = tw.Write([]byte(data))
	_ = tw.Close()
	p, err := svc.Upload(context.Background(), contentpackapp.PlatformInput{Name: name, Version: "1", Kind: contentpack.KindWordlist}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	return h, svc, p
}

// readonly and ops admins read, and are refused (403) every write whatever
// they send.
func TestAdminContentPacks_WritesNeedSuperAdmin_DB(t *testing.T) {
	for _, role := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin} {
		h, _, p := contentPackHarness(t)
		channel := "/api/v1/admin/content-packs/channels/stable"
		revoke := "/api/v1/admin/content-packs/" + p.ID.String() + "/revoke"
		a := h.newAdmin(role)
		a.verify()
		if code, _ := a.do(http.MethodGet, "/api/v1/admin/content-packs/", nil, false); code != http.StatusOK {
			t.Fatalf("%s read: %d", role, code)
		}
		if code, body := a.do(http.MethodPut, channel, map[string]string{"pack_id": p.ID.String(), "reason": "r", "totp_code": a.freshCode(true)}, true); code != http.StatusForbidden {
			t.Fatalf("%s set channel: %d %s, want 403", role, code, body)
		}
		if code, _ := a.do(http.MethodPost, revoke, map[string]string{"reason": "r", "totp_code": a.freshCode(true)}, true); code != http.StatusForbidden {
			t.Fatalf("%s revoke: %d, want 403", role, code)
		}
	}
}

// A super admin needs a reason and a fresh authenticator code; the change
// is audited with the reason.
func TestAdminContentPacks_StepUpAndAudit_DB(t *testing.T) {
	h, svc, p := contentPackHarness(t)
	name := p.Name
	channel := "/api/v1/admin/content-packs/channels/stable"
	revoke := "/api/v1/admin/content-packs/" + p.ID.String() + "/revoke"
	su := h.newAdmin(admin.AdminRoleSuperAdmin)
	su.verify()
	// No reason: 400; no code: STEP_UP_REQUIRED; wrong code: 401.
	if code, _ := su.do(http.MethodPut, channel, map[string]string{"pack_id": p.ID.String(), "totp_code": su.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	if code, body := su.do(http.MethodPut, channel, map[string]string{"pack_id": p.ID.String(), "reason": "promote"}, true); code != http.StatusUnauthorized || !strings.Contains(body, "STEP_UP_REQUIRED") {
		t.Fatalf("no code: %d %s", code, body)
	}
	if code, _ := su.do(http.MethodPost, revoke, map[string]string{"reason": "bad", "totp_code": "000000"}, true); code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", code)
	}
	if code, _ := su.do(http.MethodPost, "/api/v1/admin/content-packs/import",
		map[string]any{"name": "x", "version": "1", "kind": "wordlist", "url": "https://example.org/x.tar", "digest": "sha256:" + strings.Repeat("a", 64), "reason": "upstream"}, true); code != http.StatusUnauthorized {
		t.Fatalf("import without a code: %d", code)
	}
	if ch, _ := svc.Channels(context.Background()); len(ch) != 0 {
		for _, c := range ch {
			if c.Name == name {
				t.Fatal("a refused request moved a channel")
			}
		}
	}

	// With a reason and a fresh code: done, and audited with the reason.
	code, body := su.do(http.MethodPut, channel, map[string]string{"pack_id": p.ID.String(), "reason": "release 1 is good", "totp_code": su.freshCode(true)}, true)
	if code != http.StatusOK {
		t.Fatalf("set channel: %d %s", code, body)
	}
	var got handler.ContentChannelResponse
	_ = json.Unmarshal([]byte(body), &got)
	if got.Name != name || got.Channel != "stable" {
		t.Fatalf("channel %+v", got)
	}
	var reason string
	if err := h.db.QueryRow(`SELECT request_body->>'reason' FROM admin_audit_logs WHERE admin_id = $1 AND action = $2`,
		su.a.ID().String(), handler.AdminActionContentPackSetChannel).Scan(&reason); err != nil || reason != "release 1 is good" {
		t.Fatalf("audit row: %q %v", reason, err)
	}
}
