package audit

import "context"

// scimTokenActorCtxKey marks a request authenticated by a tenant SCIM token.
type scimTokenActorCtxKey struct{}

type scimTokenActor struct {
	id     string
	prefix string
}

// WithSCIMTokenActor records on ctx that the caller is the organization's
// identity provider, authenticated with the SCIM token tokenID (non-secret
// prefix tokenPrefix). LogEvent then stamps every audit entry written under
// ctx with the token, so a member added, suspended or re-roled by SCIM names
// the exact credential that did it (23b S-H1).
func WithSCIMTokenActor(ctx context.Context, tokenID, tokenPrefix string) context.Context {
	return context.WithValue(ctx, scimTokenActorCtxKey{}, scimTokenActor{id: tokenID, prefix: tokenPrefix})
}

// scimTokenActorFrom returns the SCIM token recorded by WithSCIMTokenActor, if any.
func scimTokenActorFrom(ctx context.Context) (scimTokenActor, bool) {
	if ctx == nil {
		return scimTokenActor{}, false
	}
	a, ok := ctx.Value(scimTokenActorCtxKey{}).(scimTokenActor)
	return a, ok && a.id != ""
}

// SCIMTokenActor returns the SCIM token recorded on ctx by WithSCIMTokenActor.
func SCIMTokenActor(ctx context.Context) (tokenID, tokenPrefix string, ok bool) {
	a, ok := scimTokenActorFrom(ctx)
	return a.id, a.prefix, ok
}
