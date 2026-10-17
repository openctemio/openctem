package admin

// Console WebAuthn authenticators and recovery codes (RFC-078, console part).
// The relying party is the console's own origin, so a credential registered
// here can never be exercised by a page on another origin.

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// MaxWebAuthnCredentials caps the authenticators of one administrator.
	MaxWebAuthnCredentials = 10
	// MinWebAuthnCredentialsRequired is how many authenticators an administrator
	// keeps while the "require WebAuthn" policy is on, so losing one key never
	// locks them out.
	MinWebAuthnCredentialsRequired = 2
	// RecoveryCodeCount is how many one-time recovery codes one generation issues.
	RecoveryCodeCount = 10
	// CeremonyTTL bounds an open registration, sign-in or step-up ceremony.
	CeremonyTTL = 5 * time.Minute
	// MaxWebAuthnNameLength is the longest authenticator label.
	MaxWebAuthnNameLength = 64
)

// Ceremony purposes: one open ceremony per console session and purpose.
const (
	CeremonyRegister = "register"
	CeremonyLogin    = "login"
	CeremonyStepUp   = "step_up"
)

// WebAuthnCredential is one registered console authenticator (public key only).
type WebAuthnCredential struct {
	ID             shared.ID
	AdminID        shared.ID
	CredentialID   []byte
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	Attachment     string
	AttestationFmt string
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	Name           string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// NormalizeWebAuthnName trims a user-given authenticator label and checks it.
func NormalizeWebAuthnName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if utf8.RuneCountInString(name) > MaxWebAuthnNameLength {
		return "", fmt.Errorf("%w: name is at most %d characters", shared.ErrValidation, MaxWebAuthnNameLength)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: name has a control character", shared.ErrValidation)
		}
	}
	return name, nil
}

// FactorRepository persists console authenticators, recovery codes and the
// single-use ceremony state.
type FactorRepository interface {
	ListWebAuthnCredentials(ctx context.Context, adminID shared.ID) ([]*WebAuthnCredential, error)
	// CreateWebAuthnCredential stores a new authenticator. It returns
	// ErrWebAuthnCredentialExists when the credential id is registered already
	// (to anyone), and ErrTooManyWebAuthnCredentials at the cap.
	CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	// RecordWebAuthnUse stores the counter and backup state of a verified
	// assertion. It refuses (returns false) when signCount does not move
	// forward for a counter-keeping authenticator, atomically.
	RecordWebAuthnUse(ctx context.Context, adminID, id shared.ID, signCount uint32, backupState bool, at time.Time) (bool, error)
	RenameWebAuthnCredential(ctx context.Context, adminID, id shared.ID, name string) error
	// DeleteWebAuthnCredential removes one authenticator of adminID, keeping at
	// least keep of them: ErrLastWebAuthnCredential when it would drop below.
	DeleteWebAuthnCredential(ctx context.Context, adminID, id shared.ID, keep int) error
	// DeleteFactorsForAdmin removes every authenticator and recovery code (the
	// super-admin reset of a lost-device administrator).
	DeleteFactorsForAdmin(ctx context.Context, adminID shared.ID) error

	// ReplaceRecoveryCodes drops every code of adminID and stores the new hashes.
	ReplaceRecoveryCodes(ctx context.Context, adminID shared.ID, hashes []string, at time.Time) error
	// UseRecoveryCode marks an unused code spent, atomically; false when no
	// unused code has that hash.
	UseRecoveryCode(ctx context.Context, adminID shared.ID, hash string, at time.Time) (bool, error)
	// CountRecoveryCodes returns the unused codes of adminID.
	CountRecoveryCodes(ctx context.Context, adminID shared.ID) (int, error)

	// SaveCeremony stores (replacing) the open ceremony of a console session.
	SaveCeremony(ctx context.Context, sessionID shared.ID, purpose string, data []byte, expiresAt time.Time) error
	// TakeCeremony removes and returns the open ceremony; ErrCeremonyNotFound
	// when there is none or it has expired. A ceremony is used at most once.
	TakeCeremony(ctx context.Context, sessionID shared.ID, purpose string, now time.Time) ([]byte, error)
}

// Factor errors.
var (
	ErrWebAuthnUnavailable        = fmt.Errorf("%w: WebAuthn is not configured for the console", shared.ErrForbidden)
	ErrWebAuthnCredentialExists   = fmt.Errorf("%w: this authenticator is already registered", shared.ErrConflict)
	ErrTooManyWebAuthnCredentials = fmt.Errorf("%w: at most %d authenticators", shared.ErrValidation, MaxWebAuthnCredentials)
	ErrLastWebAuthnCredential     = fmt.Errorf("%w: keep at least the required number of authenticators", shared.ErrConflict)
	ErrWebAuthnCredentialNotFound = fmt.Errorf("%w: authenticator not found", shared.ErrNotFound)
	ErrCeremonyNotFound           = fmt.Errorf("%w: no open WebAuthn request; start again", shared.ErrUnauthorized)
	ErrInvalidAssertion           = fmt.Errorf("%w: the authenticator response was not accepted", shared.ErrUnauthorized)
	ErrInvalidRecoveryCode        = fmt.Errorf("%w: invalid or already used recovery code", shared.ErrUnauthorized)
	ErrWebAuthnRequired           = fmt.Errorf("%w: use your security key or passkey", shared.ErrForbidden)
	ErrFactorEnrollmentRequired   = fmt.Errorf("%w: register your security keys and recovery codes first", shared.ErrForbidden)
	ErrPolicyActorNotCompliant    = fmt.Errorf("%w: register at least %d authenticators and recovery codes before requiring WebAuthn", shared.ErrConflict, MinWebAuthnCredentialsRequired)
	ErrConsoleMFAPolicyConflict   = fmt.Errorf("%w: the policy changed since it was read", shared.ErrConflict)
)

// ConsoleMFAPolicy is the platform setting "require WebAuthn for the console".
type ConsoleMFAPolicy struct {
	RequireWebAuthn bool `json:"require_webauthn"`
	// GraceUntil is when administrators who hold no security key yet lose
	// TOTP sign-in under the policy (set when the policy is switched on).
	// Absent while the policy is on means the grace is over.
	GraceUntil *time.Time `json:"grace_until,omitempty"`
}

// DefaultWebAuthnGrace is how long, from the policy switch, an administrator
// without a security key may still sign in with TOTP to enroll one.
const DefaultWebAuthnGrace = 7 * 24 * time.Hour

// ConsoleMFAPolicyKey is the platform_settings key of ConsoleMFAPolicy.
const ConsoleMFAPolicyKey = "console_mfa_policy"

// FactorStatus is an administrator's standing against the console MFA policy.
type FactorStatus struct {
	WebAuthnCount      int
	RecoveryCodesLeft  int
	TOTPEnabled        bool
	PolicyRequires     bool
	BreakGlassExempted bool
	// GraceUntil is the policy's enrollment deadline for TOTP-only
	// administrators; GraceOver is true once it has passed (or none is set).
	GraceUntil *time.Time
	GraceOver  bool
}

// Compliant reports whether the administrator meets "require WebAuthn": at
// least MinWebAuthnCredentialsRequired authenticators and unused recovery codes.
func (f FactorStatus) Compliant() bool {
	return f.WebAuthnCount >= MinWebAuthnCredentialsRequired && f.RecoveryCodesLeft > 0
}

// EnrollmentRequired reports whether a session must stay on the enrollment
// pages: the policy is on, this administrator is not exempt and not compliant.
func (f FactorStatus) EnrollmentRequired() bool {
	return f.PolicyRequires && !f.BreakGlassExempted && !f.Compliant()
}

// TOTPAllowed reports whether a TOTP code may prove this administrator. Under
// "require WebAuthn" an administrator who holds an authenticator must use it
// (TOTP can be relayed by a phishing proxy); one who has none yet may use TOTP
// to reach the enrollment pages until the grace deadline, then is refused.
// Break-glass accounts keep TOTP.
func (f FactorStatus) TOTPAllowed() bool {
	return !f.PolicyRequires || f.BreakGlassExempted || (f.WebAuthnCount == 0 && !f.GraceOver)
}
