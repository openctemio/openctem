// Package session provides public types and helpers reusable across the codebase.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Session represents an authentication session.
type Session struct {
	id                shared.ID
	userID            shared.ID
	accessTokenHash   string // SHA256 hash of the access token
	ipAddress         string
	userAgent         string
	deviceFingerprint string
	expiresAt         time.Time
	lastActivityAt    time.Time
	status            Status
	authMethod        AuthMethod
	// Federated IdP session binding (OIDC Back-Channel Logout 1.0). Populated
	// only for OIDC/OAuth sessions whose verified id_token carried these claims;
	// empty for local password and SAML sessions.
	idpIssuer string // id_token iss — scopes back-channel logout per-provider
	idpSID    string // id_token sid — IdP session id
	idpSub    string // id_token sub — IdP subject
	// idpTenantID is the organization whose own SAML/OIDC identity provider
	// issued this session. Zero for password sessions, social OAuth and
	// sessions created before it was recorded. Only that organization treats
	// the session as an SSO sign-in (see AuthMethodFor).
	idpTenantID shared.ID
	// mfaEvidence: the identity provider proved a second factor for this
	// sign-in (OIDC amr/acr, SAML AuthnContext). False when it did not say.
	mfaEvidence bool
	createdAt   time.Time
	updatedAt   time.Time
}

// MFAEvidence reports whether the identity provider proved a second factor
// for this federated sign-in.
func (s *Session) MFAEvidence() bool { return s.mfaEvidence }

// SetMFAEvidence records whether the identity provider proved a second factor.
func (s *Session) SetMFAEvidence(v bool) { s.mfaEvidence = v }

// New creates a new session.
func New(
	userID shared.ID,
	accessToken string,
	ipAddress string,
	userAgent string,
	sessionDuration time.Duration,
) (*Session, error) {
	if userID.IsZero() {
		return nil, shared.ErrValidation
	}
	if accessToken == "" {
		return nil, shared.ErrValidation
	}

	now := time.Now()
	return &Session{
		id:              shared.NewID(),
		userID:          userID,
		accessTokenHash: hashToken(accessToken),
		ipAddress:       ipAddress,
		userAgent:       userAgent,
		expiresAt:       now.Add(sessionDuration),
		lastActivityAt:  now,
		status:          StatusActive,
		authMethod:      AuthMethodPassword,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// NewWithID creates a new session entity with a pre-generated ID.
// Use this when you need the session ID before creating the session (e.g., for JWT).
func NewWithID(
	id shared.ID,
	userID shared.ID,
	accessToken string,
	ipAddress string,
	userAgent string,
	sessionDuration time.Duration,
) (*Session, error) {
	if id.IsZero() {
		return nil, shared.ErrValidation
	}
	if userID.IsZero() {
		return nil, shared.ErrValidation
	}
	if accessToken == "" {
		return nil, shared.ErrValidation
	}

	now := time.Now()
	return &Session{
		id:              id,
		userID:          userID,
		accessTokenHash: hashToken(accessToken),
		ipAddress:       ipAddress,
		userAgent:       userAgent,
		expiresAt:       now.Add(sessionDuration),
		lastActivityAt:  now,
		status:          StatusActive,
		authMethod:      AuthMethodPassword,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// Reconstitute creates a session from persisted data.
func Reconstitute(
	id shared.ID,
	userID shared.ID,
	accessTokenHash string,
	ipAddress string,
	userAgent string,
	deviceFingerprint string,
	expiresAt time.Time,
	lastActivityAt time.Time,
	status Status,
	authMethod AuthMethod,
	idpIssuer string,
	idpSID string,
	idpSub string,
	createdAt time.Time,
	updatedAt time.Time,
) *Session {
	if authMethod == "" {
		authMethod = AuthMethodPassword
	}
	return &Session{
		id:                id,
		userID:            userID,
		accessTokenHash:   accessTokenHash,
		ipAddress:         ipAddress,
		userAgent:         userAgent,
		deviceFingerprint: deviceFingerprint,
		expiresAt:         expiresAt,
		lastActivityAt:    lastActivityAt,
		status:            status,
		authMethod:        authMethod,
		idpIssuer:         idpIssuer,
		idpSID:            idpSID,
		idpSub:            idpSub,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
	}
}

// Getters

// ID returns the session ID.
func (s *Session) ID() shared.ID {
	return s.id
}

// UserID returns the user ID associated with this session.
func (s *Session) UserID() shared.ID {
	return s.userID
}

// AccessTokenHash returns the hash of the access token.
func (s *Session) AccessTokenHash() string {
	return s.accessTokenHash
}

// IPAddress returns the IP address from which the session was created.
func (s *Session) IPAddress() string {
	return s.ipAddress
}

// UserAgent returns the user agent string.
func (s *Session) UserAgent() string {
	return s.userAgent
}

// DeviceFingerprint returns the device fingerprint.
func (s *Session) DeviceFingerprint() string {
	return s.deviceFingerprint
}

// ExpiresAt returns when the session expires.
func (s *Session) ExpiresAt() time.Time {
	return s.expiresAt
}

// LastActivityAt returns the last activity time.
func (s *Session) LastActivityAt() time.Time {
	return s.lastActivityAt
}

// Status returns the session status.
func (s *Session) Status() Status {
	return s.status
}

// AuthMethod returns how the session was authenticated (password vs federated
// SSO/SAML). Used by the per-tenant SSO-enforcement gate; the zero value is
// password (fail-safe for rows written before this field existed).
func (s *Session) AuthMethod() AuthMethod {
	if s.authMethod == "" {
		return AuthMethodPassword
	}
	return s.authMethod
}

// SetAuthMethod records how the session was authenticated. Callers stamp the
// federated flows (SSO/OAuth = AuthMethodSSO, SAML = AuthMethodSAML) BEFORE the
// session is persisted; local password logins keep the AuthMethodPassword
// default. This is the discriminator the SSO-enforcement gate reads.
func (s *Session) SetAuthMethod(m AuthMethod) {
	s.authMethod = m
	s.updatedAt = time.Now()
}

// SetIDPTenant records the organization whose own identity provider issued
// this federated session. Call it only from an organization's SAML/OIDC login,
// never from social OAuth or a password login. It is set once, before the
// session is persisted (the repository also uses it when loading a row), so it
// does not touch updatedAt.
func (s *Session) SetIDPTenant(tenantID shared.ID) {
	s.idpTenantID = tenantID
}

// IDPTenantID returns the organization whose identity provider issued this
// session, or the zero ID when no organization did.
func (s *Session) IDPTenantID() shared.ID { return s.idpTenantID }

// FederatedFor reports whether this session is an SSO sign-in OF the given
// organization: federated AND issued by that organization's own identity
// provider. Only then is the session exempt from that organization's SSO
// enforcement and 2FA requirement. A session from another organization's IdP,
// from social OAuth, or recorded before the issuing organization was stored is
// not (fail closed).
func (s *Session) FederatedFor(tenantID string) bool {
	if !s.AuthMethod().IsFederated() || s.idpTenantID.IsZero() {
		return false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	return s.idpTenantID.Equals(tid)
}

// AuthMethodFor returns how the session counts for the given organization:
// its real federated method when FederatedFor(tenantID), otherwise password.
// This is the value minted into a tenant-scoped access token's auth_method
// claim, so the per-request SSO gate makes the same decision as token mint.
func (s *Session) AuthMethodFor(tenantID string) AuthMethod {
	if s.FederatedFor(tenantID) {
		return s.AuthMethod()
	}
	return AuthMethodPassword
}

// IDPIssuer returns the verified id_token issuer bound to this session (empty
// for local/SAML sessions). Used to scope OIDC back-channel logout per-provider.
func (s *Session) IDPIssuer() string { return s.idpIssuer }

// IDPSID returns the id_token session id (sid) bound to this session, or empty.
func (s *Session) IDPSID() string { return s.idpSID }

// IDPSub returns the id_token subject (sub) bound to this session, or empty.
func (s *Session) IDPSub() string { return s.idpSub }

// SetFederatedBinding records the IdP session binding (issuer/sid/sub) captured
// from the verified id_token at federated login, so an OIDC Back-Channel Logout
// can later revoke exactly the matching session(s). Callers stamp it BEFORE the
// session is persisted. Empty values are stored as-is (a provider may omit sid
// or sub). Identity metadata only — does not bump updatedAt.
func (s *Session) SetFederatedBinding(issuer, sid, sub string) {
	s.idpIssuer = issuer
	s.idpSID = sid
	s.idpSub = sub
}

// CreatedAt returns when the session was created.
func (s *Session) CreatedAt() time.Time {
	return s.createdAt
}

// UpdatedAt returns when the session was last updated.
func (s *Session) UpdatedAt() time.Time {
	return s.updatedAt
}

// Domain methods

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.expiresAt)
}

// IsActive returns true if the session is active and not expired.
func (s *Session) IsActive() bool {
	return s.status == StatusActive && !s.IsExpired()
}

// VerifyToken verifies if the provided token matches this session.
func (s *Session) VerifyToken(token string) bool {
	return s.accessTokenHash == hashToken(token)
}

// UpdateActivity updates the last activity time.
func (s *Session) UpdateActivity() {
	s.lastActivityAt = time.Now()
	s.updatedAt = time.Now()
}

// SetDeviceFingerprint sets the device fingerprint.
func (s *Session) SetDeviceFingerprint(fingerprint string) {
	s.deviceFingerprint = fingerprint
	s.updatedAt = time.Now()
}

// Revoke marks the session as revoked.
func (s *Session) Revoke() error {
	if s.status == StatusRevoked {
		return ErrSessionRevoked
	}
	s.status = StatusRevoked
	s.updatedAt = time.Now()
	return nil
}

// Expire marks the session as expired.
func (s *Session) Expire() error {
	if s.status != StatusActive {
		return ErrSessionRevoked
	}
	s.status = StatusExpired
	s.updatedAt = time.Now()
	return nil
}

// Helper functions

// hashToken creates a SHA256 hash of the token.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashToken is exported for use in repositories.
func HashToken(token string) string {
	return hashToken(token)
}
