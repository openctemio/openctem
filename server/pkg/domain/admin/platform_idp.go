package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlatformIdP is the identity provider platform administrators may sign in to
// the console with (RFC-022 revision 4). It is platform-level and unrelated to
// any organization's identity providers. OIDC only.
type PlatformIdP struct {
	Enabled     bool
	DisplayName string
	Issuer      string
	ClientID    string
	// ClientSecretEncrypted is AES-GCM ciphertext; the API never returns it.
	ClientSecretEncrypted string
	RedirectURI           string
	Scopes                []string

	// Endpoints from the issuer's discovery document, pinned when saved.
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	// TokenEndpointAuthMethod is client_secret_basic or client_secret_post.
	TokenEndpointAuthMethod string

	// RequireIdP refuses the local password path for non-break-glass admins.
	RequireIdP bool
	// TrustedACRValues / TrustedAMRValues opt in to accepting the IdP's MFA in
	// place of the console TOTP. Empty (the default): TOTP is always required.
	TrustedACRValues []string
	TrustedAMRValues []string

	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Enforced reports whether the local password path is refused for
// non-break-glass administrators.
func (p *PlatformIdP) Enforced() bool { return p != nil && p.Enabled && p.RequireIdP }

// TrustsIdPMFA reports whether any IdP MFA claim is trusted.
func (p *PlatformIdP) TrustsIdPMFA() bool {
	return p != nil && (len(p.TrustedACRValues) > 0 || len(p.TrustedAMRValues) > 0)
}

// IdPLoginState is one in-flight platform IdP sign-in (single use).
type IdPLoginState struct {
	StateHash             string
	Nonce                 string
	CodeVerifierEncrypted string
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

// IdPLoginStateTTL bounds how long the user may take at the IdP.
const IdPLoginStateTTL = 10 * time.Minute

// PlatformIdPRepository persists the platform IdP configuration and in-flight
// sign-ins.
type PlatformIdPRepository interface {
	// Get returns ErrPlatformIdPNotConfigured when there is none.
	Get(ctx context.Context) (*PlatformIdP, error)
	// Save upserts the configuration under the roster lock. It refuses with
	// ErrLastLocalAdmin when the result enforces "require IdP" but no active
	// break-glass super admin exists. clearBindings removes every
	// administrator's IdP binding in the same transaction (issuer changed).
	Save(ctx context.Context, p *PlatformIdP, clearBindings bool) error
	// Delete removes the configuration (and with it "require IdP").
	Delete(ctx context.Context) error

	CreateLoginState(ctx context.Context, s *IdPLoginState) error
	// ConsumeLoginState deletes and returns the unexpired state with this hash,
	// or ErrIdPLoginStateNotFound.
	ConsumeLoginState(ctx context.Context, stateHash string, now time.Time) (*IdPLoginState, error)
	DeleteExpiredLoginStates(ctx context.Context, now time.Time) error
}

// Platform IdP errors.
var (
	ErrPlatformIdPNotConfigured = fmt.Errorf("%w: no identity provider is configured for administrators", shared.ErrNotFound)
	ErrIdPLoginStateNotFound    = fmt.Errorf("%w: sign-in request not found or expired", shared.ErrNotFound)
	// ErrIdPBindingConflict: the binding cannot be made (already bound,
	// break-glass, or the identity belongs to another administrator).
	ErrIdPBindingConflict = fmt.Errorf("%w: identity provider binding conflict", shared.ErrConflict)
	// ErrIdPSignInFailed is the one error a client sees for any IdP sign-in
	// failure; the reason is audited server-side.
	ErrIdPSignInFailed = fmt.Errorf("%w: single sign-on failed", shared.ErrUnauthorized)
)
