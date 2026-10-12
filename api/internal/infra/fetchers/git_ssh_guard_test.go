package fetchers

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/net/proxy"
)

func TestIsSSHURL(t *testing.T) {
	for url, want := range map[string]bool{
		"ssh://git@github.com/acme/templates.git":     true,
		"git+ssh://git@github.com/acme/templates.git": true,
		"git@github.com:acme/templates.git":           true,
		"https://github.com/acme/templates.git":       false,
		"http://git.example.com/acme/templates.git":   false,
		"/var/lib/repo": false,
	} {
		if got := isSSHURL(url); got != want {
			t.Errorf("isSSHURL(%q) = %v, want %v", url, got, want)
		}
	}
}

// ssh clones and pulls dial through the SSRF-guarded dialer (the
// registered proxy dialer type), so a repository host that resolves to a
// blocked address at dial time is refused even after checkCloneURL passed
// (DNS rebinding); http(s) clones keep their own guarded transport.
func TestSSHProxyOptions_DialThroughTheGuard(t *testing.T) {
	opts := sshProxyOptions("git@github.com:acme/templates.git")
	if opts.URL == "" {
		t.Fatal("an ssh clone must name the guarded proxy dialer")
	}
	if o := sshProxyOptions("https://github.com/acme/templates.git"); o.URL != "" {
		t.Fatalf("an https clone must not name a proxy: %q", o.URL)
	}
	u, err := opts.FullURL()
	if err != nil {
		t.Fatal(err)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		t.Fatalf("the guarded dialer type is not registered: %v", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		t.Fatal("go-git needs a proxy.ContextDialer")
	}
	for _, addr := range []string{"127.0.0.1:22", "169.254.169.254:22", "localhost:22"} {
		_, err := cd.DialContext(context.Background(), "tcp", addr)
		if err == nil || !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("dial %s: err = %v, want refused by the ssrf guard", addr, err)
		}
	}
}
