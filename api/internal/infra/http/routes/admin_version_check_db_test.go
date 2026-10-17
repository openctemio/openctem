package routes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

// The version check through the console routes: any administrator reads the
// status; only a super admin imports a feed file, with the step-up; a bad
// file is refused with its reason and nothing is stored; every import is
// audited; no tenant token reaches the routes.
func TestAdminVersionCheck_Routes_DB(t *testing.T) {
	online := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	now := time.Now().UTC()
	feedFile := func(seq uint64) json.RawMessage {
		raw, err := releasefeed.Build(online, releasefeed.Feed{Sequence: seq, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * 24 * time.Hour),
			Releases:   []releasefeed.Release{{Version: "v99.0.0", PublishedAt: now}},
			Advisories: []releasefeed.Advisory{{ID: "OCTEM-TEST-1", Severity: "critical", Title: "test", FixedIn: "v99.0.0", PublishedAt: now}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		svc := versioncheck.New(postgres.NewVersionCheckRepository(db), versioncheck.Config{Enabled: false,
			Keys: []string{hex.EncodeToString(online.Public().(ed25519.PublicKey))}, Running: "v1.0.0"}, logger.NewNop())
		hs.AdminVersionCheck = handler.NewAdminVersionCheckHandler(svc, postgres.NewAuditLogRepository(db), logger.NewNop())
	})
	h.exec(`DELETE FROM version_check_state`)
	t.Cleanup(func() { h.exec(`DELETE FROM version_check_state`) })
	const path = "/api/v1/admin/version-check"

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, body := reader.do(http.MethodGet, path+"/", nil, false); code != http.StatusOK || !jsonHasBool(body, "configured", true) ||
		!jsonHasBool(body, "update_available", false) {
		t.Fatalf("read: %d %s", code, body)
	}
	reader.autoStepUp = true
	if code, _ := reader.do(http.MethodPost, path+"/import", feedFile(10), true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator imported a feed: %d", code)
	}

	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	super.closeStepUpWindow()
	if code, _ := super.do(http.MethodPost, path+"/import", feedFile(10), true); code != http.StatusUnauthorized {
		t.Fatalf("import without the step-up: %d", code)
	}
	super.autoStepUp = true

	// A tampered file is refused with its reason; nothing is stored.
	tampered := bytes.Replace(feedFile(11), []byte(`"payload": "`), []byte(`"payload": "A`), 1)
	if code, body := super.do(http.MethodPost, path+"/import", json.RawMessage(tampered), true); code != http.StatusBadRequest ||
		!strings.Contains(body, "RELEASE_FEED_INVALID") {
		t.Fatalf("tampered: %d %s", code, body)
	}
	code, body := super.do(http.MethodPost, path+"/import", feedFile(10), true)
	if code != http.StatusOK || !jsonHasBool(body, "update_available", true) || !strings.Contains(body, `"severity":"critical"`) ||
		!strings.Contains(body, `"source":"import"`) {
		t.Fatalf("import: %d %s", code, body)
	}
	// An older file is a rollback.
	if code, body := super.do(http.MethodPost, path+"/import", feedFile(9), true); code != http.StatusBadRequest ||
		!strings.Contains(body, "RELEASE_FEED_ROLLBACK") {
		t.Fatalf("rollback: %d %s", code, body)
	}
	if _, body := reader.do(http.MethodGet, path+"/", nil, false); !strings.Contains(body, `"latest":"v99.0.0"`) {
		t.Fatalf("read after import: %s", body)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = 'version_check.feed_imported'`, super.a.ID().String()).Scan(&n); err != nil || n != 3 {
		t.Fatalf("admin audit rows: %d %v, want 3 (refused, imported, rollback)", n, err)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(h.organization(0), "owner")
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		p := path + "/"
		if m == http.MethodPost {
			p = path + "/import"
		}
		req, _ := http.NewRequestWithContext(context.Background(), m, h.srv.URL+p, bytes.NewReader(feedFile(12)))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s %s: %d", m, p, resp.StatusCode)
		}
	}
}
