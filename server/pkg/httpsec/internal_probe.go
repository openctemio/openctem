package httpsec

import (
	"net/http"
	"time"
)

// InternalProbeClient returns a client for probing internal services whose
// URLs the operator configures (health checks of the platform's own
// components). It deliberately does NOT apply the SSRF dialer: the targets
// are private by design and come from deployment configuration, never from
// tenant input. It ignores proxy environment variables (probes must not be
// routed through, or leak to, an outbound proxy), never follows redirects,
// and times out after the given duration. Do not use it for any URL a tenant
// can influence; use SafeHTTPClient for those.
func InternalProbeClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
