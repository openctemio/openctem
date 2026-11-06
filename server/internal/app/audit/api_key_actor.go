package audit

import "context"

// apiKeyActorCtxKey marks a request authenticated by a tenant `oct_` API key.
type apiKeyActorCtxKey struct{}

type apiKeyActor struct {
	id     string
	prefix string
}

// WithAPIKeyActor records on ctx that the caller authenticated with the API key
// keyID (non-secret prefix keyPrefix). LogEvent then stamps every audit entry
// written under ctx with the key, next to the key's user as the actor, so an
// action taken with a key is never indistinguishable from one taken in that
// user's browser session.
func WithAPIKeyActor(ctx context.Context, keyID, keyPrefix string) context.Context {
	return context.WithValue(ctx, apiKeyActorCtxKey{}, apiKeyActor{id: keyID, prefix: keyPrefix})
}

// apiKeyActorFrom returns the API key recorded by WithAPIKeyActor, if any.
func apiKeyActorFrom(ctx context.Context) (apiKeyActor, bool) {
	if ctx == nil {
		return apiKeyActor{}, false
	}
	a, ok := ctx.Value(apiKeyActorCtxKey{}).(apiKeyActor)
	return a, ok && a.id != ""
}
