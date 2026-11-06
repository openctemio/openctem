package middleware

import "net/http"

// ClientIPKey is the request's client IP for keying a rate limiter: the TCP
// peer, or the forwarded address only when the peer is a trusted proxy
// (pkg/httpsec).
func ClientIPKey(r *http.Request) string { return getClientIP(r) }
