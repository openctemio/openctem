package middleware

import (
	"context"
	"sync"
)

// requestPrincipal carries who a request was authenticated as back out to the
// request log. The request log wraps the whole router, so it cannot see the
// context the authentication middleware builds further in; it puts this
// holder on the context instead and the authentication middleware fills it.
// Only identifiers are recorded (no e-mail, no name).
type requestPrincipal struct {
	mu       sync.Mutex
	userID   string
	tenantID string
	adminID  string
}

type requestPrincipalKey struct{}

func withRequestPrincipal(ctx context.Context) (context.Context, *requestPrincipal) {
	p := &requestPrincipal{}
	return context.WithValue(ctx, requestPrincipalKey{}, p), p
}

// notePrincipal records the authenticated user and tenant of ctx for the
// request log. A no-op outside the request log.
func notePrincipal(ctx context.Context) {
	p, ok := ctx.Value(requestPrincipalKey{}).(*requestPrincipal)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if v := GetUserID(ctx); v != "" {
		p.userID = v
	}
	if v := GetTenantID(ctx); v != "" {
		p.tenantID = v
	}
}

// noteAdminPrincipal records the platform administrator of ctx.
func noteAdminPrincipal(ctx context.Context, adminID string) {
	p, ok := ctx.Value(requestPrincipalKey{}).(*requestPrincipal)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.adminID = adminID
}

// attrs returns the principal's identifiers as log attributes.
func (p *requestPrincipal) attrs() []any {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []any
	if p.userID != "" && p.userID != p.adminID {
		out = append(out, "user_id", p.userID)
	}
	if p.tenantID != "" {
		out = append(out, "tenant_id", p.tenantID)
	}
	if p.adminID != "" {
		out = append(out, "admin_id", p.adminID)
	}
	return out
}
