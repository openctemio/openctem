package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/openctemio/openctem/api/pkg/logger"
)

const uiOrigin = "http://localhost:3000"

// upgradeServer exposes the handler's real upgrader (and so its CheckOrigin)
// without the auth chain ServeWS sits behind.
func upgradeServer(t *testing.T, h *Handler) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := h.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote the 403
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dialStatus(t *testing.T, url, origin string) int {
	t.Helper()
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	conn, resp, err := websocket.DefaultDialer.Dial(url, hdr)
	if err == nil {
		_ = conn.Close()
	}
	if resp == nil {
		t.Fatalf("no handshake response: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Cross-Site WebSocket Hijacking guard: a browser upgrade from a foreign
// Origin is refused, the configured UI origin (the UI proxies /ws on its own
// origin) is accepted, and a client without an Origin is allowed when it did
// not authenticate with the session cookie (a cookie-authenticated upgrade
// without an Origin is refused; covered over the real auth chain in
// routes/ws_upgrade_db_test.go).
func TestCheckOrigin_EnforcesAllowList(t *testing.T) {
	h := NewHandler(nil, logger.NewNop(), []string{uiOrigin}, "production")
	url := upgradeServer(t, h)

	if got := dialStatus(t, url, uiOrigin); got != http.StatusSwitchingProtocols {
		t.Errorf("allowed origin: status %d, want 101", got)
	}
	for _, foreign := range []string{"https://evil.example", "http://localhost:3001", "null"} {
		if got := dialStatus(t, url, foreign); got != http.StatusForbidden {
			t.Errorf("foreign origin %q: status %d, want 403", foreign, got)
		}
	}
	if got := dialStatus(t, url, ""); got != http.StatusSwitchingProtocols {
		t.Errorf("no Origin, no cookie session: status %d, want 101", got)
	}
}

func TestCheckOrigin_WildcardIgnoredInProduction(t *testing.T) {
	prod := NewHandler(nil, logger.NewNop(), []string{"*"}, "production")
	if got := dialStatus(t, upgradeServer(t, prod), "https://evil.example"); got != http.StatusForbidden {
		t.Errorf("production wildcard: status %d, want 403", got)
	}
	dev := NewHandler(nil, logger.NewNop(), []string{"*"}, "development")
	if got := dialStatus(t, upgradeServer(t, dev), "https://evil.example"); got != http.StatusSwitchingProtocols {
		t.Errorf("development wildcard: status %d, want 101", got)
	}
}
