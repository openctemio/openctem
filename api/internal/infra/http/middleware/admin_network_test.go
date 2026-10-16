package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

func TestAdminNetworkGate(t *testing.T) {
	private := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
	}
	gate := AdminNetworkGate(private, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	cases := []struct {
		name, path, remote, xff string
		want                    int
	}{
		{"console from the LAN", "/api/v1/admin/overview", "192.168.1.20:5000", "", http.StatusNoContent},
		{"console sign-in from the LAN", "/api/v1/admin/auth/session", "10.1.2.3:5000", "", http.StatusNoContent},
		{"console from the internet", "/api/v1/admin/overview", "203.0.113.9:5000", "", http.StatusForbidden},
		{"console prefix itself", "/api/v1/admin", "203.0.113.9:5000", "", http.StatusForbidden},
		{"IPv4-mapped IPv6 LAN peer", "/api/v1/admin/overview", "[::ffff:10.0.0.5]:5000", "", http.StatusNoContent},
		{"IPv6 ULA", "/api/v1/admin/overview", "[fd00::5]:5000", "", http.StatusNoContent},
		{"IPv6 internet", "/api/v1/admin/overview", "[2001:db8::1]:5000", "", http.StatusForbidden},
		{"untrusted peer cannot claim a LAN address", "/api/v1/admin/overview", "203.0.113.9:5000", "10.0.0.1", http.StatusForbidden},
		{"trusted proxy forwards an internet client", "/api/v1/admin/overview", "127.0.0.1:5000", "203.0.113.9", http.StatusForbidden},
		{"trusted proxy forwards a LAN client", "/api/v1/admin/overview", "127.0.0.1:5000", "192.168.7.7", http.StatusNoContent},
		{"tenant routes are not gated", "/api/v1/findings", "203.0.113.9:5000", "", http.StatusNoContent},
		{"a look-alike prefix is not the console", "/api/v1/administrators", "203.0.113.9:5000", "", http.StatusNoContent},
		{"unparseable peer refused", "/api/v1/admin/overview", "garbage", "", http.StatusForbidden},
	}
	prev := trustedProxies
	SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"127.0.0.1/32"}))
	t.Cleanup(func() { trustedProxies = prev })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
