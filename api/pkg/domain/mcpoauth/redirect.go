package mcpoauth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxRedirectURILen bounds a redirect URI (registered or presented).
const maxRedirectURILen = 2048

// ValidateRedirectURI checks a redirect URI a client registers or declares
// (RFC-062 MA12): an absolute URI without fragment or user info, https, or
// http on a loopback host (a native client's local listener, RFC 8252 §7.3).
// Custom schemes are refused.
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > maxRedirectURILen {
		return fmt.Errorf("%w: redirect URI is empty or too long", shared.ErrValidation)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: redirect URI must be an absolute URL", shared.ErrValidation)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil {
		return fmt.Errorf("%w: redirect URI must not carry a fragment or user info", shared.ErrValidation)
	}
	switch u.Scheme {
	case schemeHTTPS:
		return nil
	case schemeHTTP:
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%w: redirect URI must use https, or http on a loopback address", shared.ErrValidation)
}

// MatchRedirectURI reports whether presented is one of the registered
// redirect URIs. The comparison is exact string equality, with one
// exception: for an http loopback redirect URI the port may differ, because
// a native client listens on whatever port the OS gives it (RFC 8252 §7.3,
// RFC 9700 §4.1.1). Scheme, host spelling, path and query must still match
// exactly.
func MatchRedirectURI(registered []string, presented string) bool {
	if presented == "" || len(presented) > maxRedirectURILen {
		return false
	}
	for _, r := range registered {
		if r == presented {
			return true
		}
	}
	p, err := url.Parse(presented)
	if err != nil || p.Scheme != schemeHTTP || !isLoopbackHost(p.Hostname()) || p.Fragment != "" || p.User != nil {
		return false
	}
	for _, r := range registered {
		ru, err := url.Parse(r)
		if err != nil || ru.Scheme != schemeHTTP || !isLoopbackHost(ru.Hostname()) {
			continue
		}
		if ru.Hostname() == p.Hostname() && ru.EscapedPath() == p.EscapedPath() && ru.RawQuery == p.RawQuery && validPort(p.Port()) {
			return true
		}
	}
	return false
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n <= 65535 && !strings.HasPrefix(p, "0")
}

// IsLoopbackOnly reports whether every redirect URI of a client is a
// loopback address. The consent page warns about such clients: any local
// program can listen there and present the same client_id (MCP security
// considerations, localhost redirect impersonation).
func IsLoopbackOnly(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, r := range uris {
		u, err := url.Parse(r)
		if err != nil || !isLoopbackHost(u.Hostname()) {
			return false
		}
	}
	return true
}

// RedirectHost returns the host name of a redirect URI, shown on the consent
// page.
func RedirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
