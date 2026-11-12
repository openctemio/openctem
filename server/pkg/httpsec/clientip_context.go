package httpsec

import "context"

type clientIPKey struct{}

// WithClientIP returns ctx carrying the request's client IP, as ClientIP
// resolved it (the TCP peer, or the forwarded address only behind a trusted
// proxy). Services that need the address of the person they act for read it
// back with ClientIPFromContext instead of taking it as a parameter.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIPFromContext returns the client IP stored by WithClientIP, or "".
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}
