package tenant

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/emaildomain"
)

// Personal accounts and SSO exceptions (RFC-058 §9).

// PersonalAccountsPolicy says whether members with a personal address
// (gmail.com, outlook.com, ...) may use the organization.
type PersonalAccountsPolicy string

const (
	// PersonalAccountsAllowed: like any external member. The empty value
	// means this (organizations created before the policy existed).
	PersonalAccountsAllowed PersonalAccountsPolicy = "allowed"
	// PersonalAccountsAllowedWithMFA: a personal member must prove a second
	// factor to get a token for the organization (the default for new
	// organizations).
	PersonalAccountsAllowedWithMFA PersonalAccountsPolicy = "allowed_with_mfa"
	// PersonalAccountsBlocked: personal addresses cannot be invited, accept
	// an invitation, or get a token for the organization.
	PersonalAccountsBlocked PersonalAccountsPolicy = "blocked"
)

// IsValid reports whether p is known (empty counts as allowed).
func (p PersonalAccountsPolicy) IsValid() bool {
	switch p {
	case "", PersonalAccountsAllowed, PersonalAccountsAllowedWithMFA, PersonalAccountsBlocked:
		return true
	}
	return false
}

// Effective maps the empty value to allowed.
func (p PersonalAccountsPolicy) Effective() PersonalAccountsPolicy {
	if p == "" {
		return PersonalAccountsAllowed
	}
	return p
}

// MaxSSOExceptionDays bounds an SSO exception.
const MaxSSOExceptionDays = 90

// SSOException lets one named member sign in without the organization's SSO
// (with a second factor) until ExpiresAt, while SSO is enforced.
type SSOException struct {
	UserID    string    `json:"user_id"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Validate checks one exception at time now.
func (e SSOException) Validate(now time.Time) error {
	if _, err := shared.IDFromString(e.UserID); err != nil {
		return fmt.Errorf("%w: sso exception needs a valid user_id", shared.ErrValidation)
	}
	if strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 500 {
		return fmt.Errorf("%w: an sso exception needs a reason (at most 500 characters)", shared.ErrValidation)
	}
	if !e.ExpiresAt.After(now) || e.ExpiresAt.After(now.Add(MaxSSOExceptionDays*24*time.Hour)) {
		return fmt.Errorf("%w: an sso exception must expire within %d days", shared.ErrValidation, MaxSSOExceptionDays)
	}
	return nil
}

// HasSSOException reports whether userID has an unexpired SSO exception.
func (s SecuritySettings) HasSSOException(userID string, now time.Time) bool {
	for _, e := range s.SSOExceptions {
		if e.UserID == userID && e.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

// IsPersonalMember reports whether m is an external member with a personal
// address (a consumer mail domain no organization can hold).
func IsPersonalMember(m *Membership) bool {
	return m != nil && m.IsExternal() && m.HomeTenantID() == nil && emaildomain.IsConsumer(m.HomeDomain())
}
