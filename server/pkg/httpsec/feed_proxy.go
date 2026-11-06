package httpsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// The platform feed proxy: an explicit, opt-in HTTPS proxy for the
// platform's own intelligence and release fetchers (vulnerability bundles,
// KEV, EPSS, CTEM-ID catalog, public program feed, release feed), for
// installations whose only way out is a corporate proxy. Design and threat
// model: docs/architecture/outbound-requests.md, "Platform feed proxy".
//
// Only FeedHTTPClient uses it. Every other guarded client (webhooks,
// integrations, SCM, identity providers, anything an organization can point
// somewhere) never takes a proxy, from this setting or from the environment:
// a proxy would put the destination check on the proxy's side of the
// network instead of ours.
const (
	EnvFeedProxy   = "OPENCTEM_HTTPSEC_FEED_PROXY"
	EnvFeedNoProxy = "OPENCTEM_HTTPSEC_FEED_NO_PROXY"
)

// proxyResolveTimeout bounds the local look-up of a proxied destination.
const proxyResolveTimeout = 3 * time.Second

// feedProxyConfig is the parsed proxy setting.
type feedProxyConfig struct {
	proxy   *url.URL
	noProxy string
	match   func(*url.URL) (*url.URL, error)
}

// feedProxy is the setting read at start-up (nil: no proxy).
var feedProxy *feedProxyConfig

// A refused setting proxies nothing (fail closed to direct, guarded dials);
// config validation refuses to start on it (ValidateFeedProxy).
func init() {
	feedProxy, _ = parseFeedProxy(os.Getenv(EnvFeedProxy), os.Getenv(EnvFeedNoProxy))
}

const schemeHTTPS = "https"

// ValidateFeedProxy checks the feed proxy setting without applying it.
// Config validation calls it so the server refuses to start on a setting the
// clients would ignore.
func ValidateFeedProxy(proxy, noProxy string) error {
	_, err := parseFeedProxy(proxy, noProxy)
	return err
}

// FeedProxyHost returns the proxy's host:port for start-up logging ("" when
// none). Credentials are never returned.
func FeedProxyHost() string {
	if feedProxy == nil {
		return ""
	}
	return feedProxy.proxy.Host
}

func parseFeedProxy(raw, noProxy string) (*feedProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes the input, which may hold a password.
		return nil, fmt.Errorf("%s is not a URL", EnvFeedProxy)
	}
	if u.Scheme != "http" && u.Scheme != schemeHTTPS {
		return nil, fmt.Errorf("%s must be an http:// or https:// proxy URL", EnvFeedProxy)
	}
	if u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s must be scheme://[user:password@]host:port with no path, query or fragment", EnvFeedProxy)
	}
	u.Path = ""
	cfg := &feedProxyConfig{proxy: u, noProxy: strings.TrimSpace(noProxy)}
	cfg.match = (&httpproxy.Config{HTTPSProxy: u.String(), NoProxy: cfg.noProxy}).ProxyFunc()
	return cfg, nil
}

// FeedHTTPClient is the client of the platform's own feed fetchers. Without
// a feed proxy it is SafeHTTPClient. With one, https requests go through the
// proxy (CONNECT; TLS is end to end, so the certificate is still verified
// against the destination's name), and:
//
//   - the destination is still checked: a dangerous name, a blocked IP
//     literal, or a name whose local answers include a blocked address is
//     refused before the proxy sees it. A name the local resolver cannot
//     answer goes to the proxy, which resolves it (a network whose only
//     exit is the proxy usually has no outside DNS either);
//   - only https destinations are proxied; plain http and loopback names
//     take the guarded direct dial;
//   - hosts in OPENCTEM_HTTPSEC_FEED_NO_PROXY (an internal mirror) are
//     dialed directly through the guard as usual;
//   - the proxy itself may be on a private address (it is the operator's
//     own setting); loopback, link-local and metadata addresses stay
//     refused.
//
// Never use it for a URL an organization supplies.
func FeedHTTPClient(timeout time.Duration) *http.Client {
	return newFeedHTTPClient(timeout, feedProxy, defaultDialer)
}

func newFeedHTTPClient(timeout time.Duration, cfg *feedProxyConfig, d guardedDialer) *http.Client {
	c := newSafeHTTPClient(timeout, d)
	if cfg == nil {
		return c
	}
	tr, _ := c.Transport.(*http.Transport)
	proxyDial := d
	proxyDial.privateOK = true
	proxyDial.perRequest = false
	proxyAddr := canonicalAddr(cfg.proxy)
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		p, err := cfg.match(req.URL)
		if err != nil || p == nil {
			// NO_PROXY match (or localhost): the guarded direct dial decides.
			return nil, err
		}
		resolve := func(ctx context.Context, host string) error {
			_, err := resolveSafeIPsPolicy(ctx, d.resolver, host, false)
			return err
		}
		if err := checkProxiedDestination(req.Context(), resolve, req.URL.Hostname()); err != nil {
			return nil, fmt.Errorf("ssrf guard: %w", err)
		}
		return cfg.proxy, nil
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == proxyAddr {
			return proxyDial.dialContext(ctx, network, addr)
		}
		return d.dialContext(ctx, network, addr)
	}
	return c
}

// checkProxiedDestination applies the guard's destination rules to a host
// the proxy will connect to. Answers are judged by the installation's policy
// (the private ranges it opened stay reachable, as on a direct dial);
// resolve looks the name up and vets every answer.
func checkProxiedDestination(ctx context.Context, resolve func(context.Context, string) error, host string) error {
	if isDangerousHost(host) {
		return ErrBlockedDestination
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsIPBlocked(ip) {
			return ErrBlockedDestination
		}
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, proxyResolveTimeout)
	defer cancel()
	err := resolve(lctx, host)
	if errors.Is(err, ErrUnresolvable) {
		return nil // the proxy resolves it
	}
	return err
}

// canonicalAddr is the host:port the transport dials for a proxy URL.
func canonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == schemeHTTPS {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// ValidateFeedURL is ValidateURL for a platform feed URL set by the operator,
// checked at start-up: a name that does not resolve yet is accepted (the
// network may still be coming up, or only the feed proxy resolves outside
// names), because every fetch is checked again when it is made. A refused
// scheme, a dangerous name or an answer in a blocked range is an error.
func ValidateFeedURL(raw string) error {
	_, err := ValidateURL(raw)
	if errors.Is(err, ErrUnresolvable) {
		return nil
	}
	return err
}
