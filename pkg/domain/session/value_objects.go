package session

// Status represents the status of a session.
type Status string

const (
	// StatusActive indicates an active session.
	StatusActive Status = "active"
	// StatusExpired indicates an expired session.
	StatusExpired Status = "expired"
	// StatusRevoked indicates a revoked session.
	StatusRevoked Status = "revoked"
)

// IsValid checks if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// IsActive returns true if the session is active.
func (s Status) IsActive() bool {
	return s == StatusActive
}

// StatusFromString converts a string to Status.
func StatusFromString(s string) Status {
	switch s {
	case "active":
		return StatusActive
	case "expired":
		return StatusExpired
	case "revoked":
		return StatusRevoked
	default:
		return StatusActive
	}
}

// AuthMethod records HOW a session was authenticated. It is the discriminator
// the per-tenant SSO-enforcement gate uses to tell a local password login apart
// from a federated (SSO/OAuth/SAML) login: an SSO-enforced tenant refuses
// password sessions (the tenant owner is the break-glass exception) but always
// admits federated ones — an enforced tenant must always admit the very login
// method it requires. The zero value is password: fail-safe for the common case
// and backward compatible with session rows written before this field existed.
type AuthMethod string

const (
	// AuthMethodPassword marks a session created by a local email+password login.
	AuthMethodPassword AuthMethod = "password"
	// AuthMethodSSO marks a session created by a federated OIDC/OAuth flow
	// (per-tenant identity provider or social OAuth). Exempt from SSO enforcement.
	AuthMethodSSO AuthMethod = "sso"
	// AuthMethodSAML marks a session created by a validated SAML 2.0 assertion.
	// Exempt from SSO enforcement (it IS an SSO login).
	AuthMethodSAML AuthMethod = "saml"
)

// String returns the string representation of the auth method.
func (m AuthMethod) String() string {
	return string(m)
}

// IsValid reports whether the auth method is a known value.
func (m AuthMethod) IsValid() bool {
	switch m {
	case AuthMethodPassword, AuthMethodSSO, AuthMethodSAML:
		return true
	default:
		return false
	}
}

// IsFederated reports whether the session was created by an external identity
// provider (SSO/OAuth/SAML) rather than a local password. Federated sessions
// satisfy per-tenant SSO enforcement; password sessions do not. An empty/unknown
// method is treated as NOT federated (fail-closed: an unmarked session must not
// silently pass enforcement).
func (m AuthMethod) IsFederated() bool {
	return m == AuthMethodSSO || m == AuthMethodSAML
}

// AuthMethodFromString converts a persisted string to an AuthMethod, defaulting
// to password for empty/unknown values (fail-safe: an unrecognized method must
// not silently pass SSO enforcement).
func AuthMethodFromString(s string) AuthMethod {
	switch AuthMethod(s) {
	case AuthMethodSSO:
		return AuthMethodSSO
	case AuthMethodSAML:
		return AuthMethodSAML
	default:
		return AuthMethodPassword
	}
}
