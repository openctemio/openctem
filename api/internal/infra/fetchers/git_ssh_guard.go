package fetchers

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"golang.org/x/net/proxy"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// go-git's ssh transport dials on its own and has no dialer hook, so a
// repository host that passed checkCloneURL could resolve to a blocked
// address at dial time (DNS rebinding). Its one way to change the dial is a
// proxy: ssh clones and pulls name sshGuardProxyScheme as their proxy, a
// dialer type registered with golang.org/x/net/proxy that is
// httpsec.SafeDialContext. It resolves the host once, refuses a blocked
// answer and connects to the vetted address only.
const sshGuardProxyScheme = "openctem-ssrf-guard"

func init() {
	proxy.RegisterDialerType(sshGuardProxyScheme, func(*url.URL, proxy.Dialer) (proxy.Dialer, error) {
		return sshGuardDialer{}, nil
	})
}

// sshGuardDialer is the SSRF-guarded dialer of ssh clones and pulls.
type sshGuardDialer struct{}

func (sshGuardDialer) Dial(network, addr string) (net.Conn, error) {
	return httpsec.SafeDialContext(context.Background(), network, addr)
}

func (sshGuardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return httpsec.SafeDialContext(ctx, network, addr)
}

// isSSHURL reports whether rawURL is cloned over ssh: an ssh:// URL or the
// scp-like form user@host:path.
func isSSHURL(rawURL string) bool {
	if strings.HasPrefix(rawURL, "ssh://") || strings.HasPrefix(rawURL, "git+ssh://") {
		return true
	}
	return !strings.Contains(rawURL, "://") && strings.Contains(rawURL, "@") && strings.Contains(rawURL, ":")
}

// sshProxyOptions are the proxy options of a clone or pull of rawURL: the
// guarded dialer for ssh, nothing for http(s) (pinned by the transport
// installed in init) and when local repositories are allowed (tests).
func sshProxyOptions(rawURL string) transport.ProxyOptions {
	if allowLocalRepos || !isSSHURL(rawURL) {
		return transport.ProxyOptions{}
	}
	return transport.ProxyOptions{URL: sshGuardProxyScheme + "://guard"}
}
