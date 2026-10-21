package proxypool

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListEntry is one parsed line of a pasted endpoint list.
type ListEntry struct {
	Line   int // 1-based line number in the pasted text
	Scheme string
	Host   string
	Port   int
	Label  string
	// KeepCredentials: the line carried the masked marker, so the stored
	// credentials of the same endpoint are kept.
	KeepCredentials bool
	// Username and Password are set when the line carried credentials.
	Username string
	Password string
}

// HasNewCredentials reports whether the line carries credentials of its own.
func (e ListEntry) HasNewCredentials() bool { return e.Username != "" || e.Password != "" }

// Address is scheme://host:port of the entry.
func (e ListEntry) Address() string { return addressOf(e.Scheme, e.Host, e.Port) }

func (e ListEntry) key() string { return endpointKey(e.Scheme, e.Host, e.Port) }

// ListError is a pasted line that does not parse. Its message never
// repeats the line (it may carry a password).
type ListError struct {
	Line   int
	Reason string
}

func (e *ListError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }

// Code is the API error code of an invalid list.
func (e *ListError) Code() string { return "INVALID_PROXY_ENDPOINT" }

// Unwrap makes a ListError a validation error.
func (e *ListError) Unwrap() error { return shared.ErrValidation }

// ParseList parses a pasted endpoint list: one
// scheme://[user:pass@]host:port[#label] per line; blank lines and lines
// that start with "#" are ignored. Characters that are special in a URL
// ("@", ":", "#", "/") must be percent-encoded in a user name or password.
// The order of the lines is the endpoints' priority. Two lines naming the
// same endpoint are an error.
func ParseList(text string) ([]ListEntry, error) {
	if len(text) > MaxListBytes {
		return nil, &ListError{Line: 0, Reason: fmt.Sprintf("the list is larger than %d KiB", MaxListBytes>>10)}
	}
	out := make([]ListEntry, 0, 8)
	seen := map[string]int{}
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseLine(line)
		if err != nil {
			return nil, &ListError{Line: i + 1, Reason: err.Error()}
		}
		e.Line = i + 1
		if first, dup := seen[e.key()]; dup {
			return nil, &ListError{Line: i + 1, Reason: fmt.Sprintf("%s is already on line %d", e.Address(), first)}
		}
		seen[e.key()] = e.Line
		out = append(out, e)
		if len(out) > MaxEndpointsPerPool {
			return nil, &ListError{Line: i + 1, Reason: fmt.Sprintf("a pool may have at most %d endpoints", MaxEndpointsPerPool)}
		}
	}
	return out, nil
}

func parseLine(line string) (ListEntry, error) {
	var e ListEntry
	if i := strings.IndexByte(line, '#'); i >= 0 {
		e.Label = strings.TrimSpace(line[i+1:])
		line = strings.TrimSpace(line[:i])
		if utf8.RuneCountInString(e.Label) > MaxLabelLength || hasControl(e.Label) {
			return e, fmt.Errorf("the label must be at most %d characters", MaxLabelLength)
		}
	}
	if strings.ContainsAny(line, " \t") {
		return e, fmt.Errorf("an endpoint has no spaces (write it as scheme://user:password@host:port)")
	}
	if i := strings.Index(line, "://"+MaskedCredentials+"@"); i >= 0 {
		e.KeepCredentials = true
		line = line[:i] + "://" + line[i+len("://"+MaskedCredentials+"@"):]
	}
	u, err := url.Parse(line)
	if err != nil || u.Opaque != "" {
		return e, fmt.Errorf("not a proxy URL (write it as scheme://host:port)")
	}
	e.Scheme = strings.ToLower(u.Scheme)
	switch e.Scheme {
	case SchemeHTTP, SchemeHTTPS, SchemeSOCKS5, SchemeSOCKS5H:
	default:
		return e, fmt.Errorf("the scheme must be http, https, socks5 or socks5h")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
		return e, fmt.Errorf("a proxy URL has no path or query")
	}
	if u.User != nil {
		if e.KeepCredentials {
			return e, fmt.Errorf("a line keeps the stored credentials (%s) or sets new ones, not both", MaskedCredentials)
		}
		e.Username = u.User.Username()
		e.Password, _ = u.User.Password()
		if e.Username == "" {
			return e, fmt.Errorf("credentials need a user name")
		}
		if len(e.Username) > MaxCredentialLength || len(e.Password) > MaxCredentialLength ||
			hasControl(e.Username) || hasControl(e.Password) {
			return e, fmt.Errorf("the user name and password must be at most %d characters, without control characters", MaxCredentialLength)
		}
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil || portStr == "" {
		return e, fmt.Errorf("the endpoint needs a host and a port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return e, fmt.Errorf("the port must be 1 to 65535")
	}
	if err := CheckHost(host); err != nil {
		return e, err
	}
	e.Host, e.Port = strings.ToLower(strings.TrimSuffix(host, ".")), port
	return e, nil
}

// RenderList writes endpoints back as a list the console shows in the
// paste box: stored credentials appear masked, never in clear.
func RenderList(endpoints []*Endpoint) string {
	var b strings.Builder
	for i, e := range endpoints {
		if i > 0 {
			b.WriteByte('\n')
		}
		addr := e.Address()
		if e.HasCredentials() {
			addr = strings.Replace(addr, "://", "://"+MaskedCredentials+"@", 1)
		}
		b.WriteString(addr)
		if e.Label != "" {
			b.WriteString("#" + e.Label)
		}
	}
	return b.String()
}
