package email

import (
	"errors"
	"strings"
)

// RelayMode is the platform setting that decides whether an organization's
// own mail relay carries its organization mail (invitations, account setup,
// member notices, scheduled reports).
type RelayMode string

const (
	// RelayModeOff: organization mail always goes through the platform relay.
	// A stored organization relay is kept but inactive.
	RelayModeOff RelayMode = "off"
	// RelayModeVerifiedSender: the relay is used only when the sender
	// address belongs to a DNS-verified domain of the organization and the
	// relay meets the managed transport rules (ValidateTenantRelay).
	RelayModeVerifiedSender RelayMode = "verified_sender"
	// RelayModeOn: the relay is used as configured (the transport rule of
	// ValidateTenantRelay still applies); no sender-domain rule.
	RelayModeOn RelayMode = "on"
)

// ParseRelayMode reads a mode name (case-insensitive).
func ParseRelayMode(s string) (RelayMode, bool) {
	m := RelayMode(strings.ToLower(strings.TrimSpace(s)))
	switch m {
	case RelayModeOff, RelayModeVerifiedSender, RelayModeOn:
		return m, true
	}
	return "", false
}

// DefaultRelayMode is the mode while nothing is stored: "on" on a
// self-managed install (the operator trusts its own organizations),
// "verified_sender" on a managed service.
func DefaultRelayMode(managed bool) RelayMode {
	if managed {
		return RelayModeVerifiedSender
	}
	return RelayModeOn
}

// ErrTenantRelayUnusable means an organization has an active relay that
// cannot be used right now (sender domain not verified, rules not met, not
// connected). Content mail does not fall back to the platform relay then.
var ErrTenantRelayUnusable = errors.New("the organization's mail relay cannot be used")

type tenantRelayUnusable struct{ cause error }

func (e tenantRelayUnusable) Error() string {
	return ErrTenantRelayUnusable.Error() + ": " + e.cause.Error()
}

func (e tenantRelayUnusable) Unwrap() []error { return []error{ErrTenantRelayUnusable, e.cause} }

// RelayUnusable is ErrTenantRelayUnusable with the reason it failed. The
// reason must be one of this package's or the resolver's fixed sentences,
// never a lower error's text.
func RelayUnusable(reason error) error { return tenantRelayUnusable{reason} }
