package evidence

import (
	"net/url"
	"strconv"
	"strings"
)

// ParseRawRequest reads a raw HTTP/1.x request as tools print it
// ("GET /path HTTP/1.1\r\nHost: h\r\n\r\nbody"). base is the URL the request
// was sent to (the tool's matched-at), used to build an absolute URL when the
// request line carries only a path. It never fails: what cannot be parsed is
// kept as the body.
func ParseRawRequest(raw, base string) *HTTPRequest {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	head, body := splitHead(raw)
	lines := splitLines(head)
	q := &HTTPRequest{Body: body}
	if len(lines) == 0 {
		return q
	}
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 && isMethod(parts[0]) {
		q.Method = parts[0]
		q.URL = parts[1]
		if len(parts) >= 3 {
			q.HTTPVersion = parts[2]
		}
		lines = lines[1:]
	}
	q.Headers = parseHeaders(lines)
	q.URL = absoluteURL(q.URL, base, q.Headers)
	q.BodySize = len(body)
	return q
}

// ParseRawResponse reads a raw HTTP/1.x response ("HTTP/1.1 200 OK\r\n...").
func ParseRawResponse(raw string) *HTTPResponse {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	head, body := splitHead(raw)
	lines := splitLines(head)
	s := &HTTPResponse{Body: body}
	if len(lines) == 0 {
		return s
	}
	if strings.HasPrefix(lines[0], "HTTP/") {
		ver, rest, _ := strings.Cut(lines[0], " ")
		code, reason, _ := strings.Cut(strings.TrimSpace(rest), " ")
		s.HTTPVersion = ver
		if n, err := strconv.Atoi(code); err == nil && n >= 100 && n <= 999 {
			s.Status = n
		}
		s.Reason = reason
		lines = lines[1:]
	}
	s.Headers = parseHeaders(lines)
	s.BodySize = len(body)
	if s.Status == 0 && len(s.Headers) == 0 {
		// Not a response head at all: keep everything as the body.
		s.Body, s.BodySize = raw, len(raw)
	}
	return s
}

func splitHead(raw string) (string, string) {
	if h, b, ok := strings.Cut(raw, "\r\n\r\n"); ok {
		return h, b
	}
	if h, b, ok := strings.Cut(raw, "\n\n"); ok {
		return h, b
	}
	return raw, ""
}

func splitLines(head string) []string {
	head = strings.ReplaceAll(head, "\r\n", "\n")
	out := strings.Split(head, "\n")
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	return out
}

func parseHeaders(lines []string) []Header {
	hs := make([]Header, 0, len(lines))
	for _, l := range lines {
		name, value, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		hs = append(hs, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	return hs
}

func isMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE":
		return true
	}
	return false
}

// absoluteURL turns a request-line target into an absolute URL using the
// scheme of base and the Host header (or base's host).
func absoluteURL(target, base string, hs []Header) string {
	if strings.Contains(target, "://") {
		return target
	}
	b, err := url.Parse(base)
	if err != nil || b.Scheme == "" {
		return target
	}
	host := b.Host
	for _, h := range hs {
		if strings.EqualFold(h.Name, "host") && h.Value != "" {
			host = h.Value
		}
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return b.Scheme + "://" + host + target
}
