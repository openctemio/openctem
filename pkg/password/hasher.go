// Package password provides secure password hashing and validation.
package password

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Errors for password operations.
var (
	ErrPasswordTooShort    = errors.New("password is too short")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoNumber    = errors.New("password must contain at least one number")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
	ErrPasswordMismatch    = errors.New("password does not match")
	ErrInvalidHash         = errors.New("invalid password hash")
)

// DefaultCost is the default bcrypt cost factor.
// This provides a good balance between security and performance.
const DefaultCost = 12

// Policy defines password requirements.
type Policy struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultPolicy returns a sensible default password policy.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false,
	}
}

// Hasher provides password hashing and verification operations.
type Hasher struct {
	cost   int
	policy Policy
}

// Option configures the Hasher.
type Option func(*Hasher)

// WithCost sets the bcrypt cost factor.
func WithCost(cost int) Option {
	return func(h *Hasher) {
		if cost >= bcrypt.MinCost && cost <= bcrypt.MaxCost {
			h.cost = cost
		}
	}
}

// WithPolicy sets the password policy.
func WithPolicy(policy Policy) Option {
	return func(h *Hasher) {
		h.policy = policy
	}
}

// New creates a new password hasher with the given options.
func New(opts ...Option) *Hasher {
	h := &Hasher{
		cost:   DefaultCost,
		policy: DefaultPolicy(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Hash hashes a password using bcrypt.
func (h *Hasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Verify checks if a password matches a hash.
func (h *Hasher) Verify(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return ErrInvalidHash
	}
	return nil
}

// Validate checks if a password meets the policy requirements.
func (h *Hasher) Validate(password string) error {
	return ValidateWithPolicy(password, h.policy)
}

// ValidateWithPolicy validates a password against a specific policy.
func ValidateWithPolicy(password string, policy Policy) error {
	if len(password) < policy.MinLength {
		return ErrPasswordTooShort
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return ErrPasswordNoUppercase
	}
	if policy.RequireLower && !hasLower {
		return ErrPasswordNoLowercase
	}
	if policy.RequireNumber && !hasNumber {
		return ErrPasswordNoNumber
	}
	if policy.RequireSpecial && !hasSpecial {
		return ErrPasswordNoSpecial
	}

	return nil
}

// GenerateSecureToken generates a cryptographically secure random token.
// The token is URL-safe base64 encoded.
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateResetToken generates a password reset token.
// Returns a 32-byte (256-bit) secure random token.
func GenerateResetToken() (string, error) {
	return GenerateSecureToken(32)
}

// GenerateVerificationToken generates an email verification token.
// Returns a 32-byte (256-bit) secure random token.
func GenerateVerificationToken() (string, error) {
	return GenerateSecureToken(32)
}

// NeedsRehash checks if a hash needs to be updated due to cost changes.
func (h *Hasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost != h.cost
}
