package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefreshClientBinding(t *testing.T) {
	ok := strings.Repeat("ab12", 16) // 64 hex characters, as the web server sends
	cases := []struct {
		name, value, want string
	}{
		{"absent", "", ""},
		{"well formed", ok, ok},
		{"url-safe base64", strings.Repeat("A-_z", 8), strings.Repeat("A-_z", 8)},
		{"too short", "abc", ""},
		{"too long", strings.Repeat("a", 129), ""},
		{"junk characters", strings.Repeat("a", 40) + "\"; x", ""},
		{"spaces", strings.Repeat("a b ", 10), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/auth/refresh", nil)
			if tc.value != "" {
				r.Header.Set(RefreshClientBindingHeader, tc.value)
			}
			if got := refreshClientBinding(r); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
