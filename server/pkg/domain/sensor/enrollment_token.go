package sensor

// Organization enrollment tokens (docs/architecture/sensor-pairing.md,
// "Enrollment tokens"): an organization administrator issues a token for
// unattended installs; a sensor that starts pairing with it joins that
// organization with the token's presets, at trust level New.

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds of an organization enrollment token (the table checks them too).
const (
	MaxEnrollmentTokenTTL      = 30 * 24 * time.Hour
	MinEnrollmentTokenTTL      = time.Hour
	DefaultEnrollmentTokenTTL  = 24 * time.Hour
	MaxEnrollmentTokenUses     = 1000
	DefaultEnrollmentTokenUses = 10
	MaxEnrollmentTokenLabels   = 20
	MaxEnrollmentTokenCIDRs    = 20
)

// Token states a list shows (computed, never stored).
const (
	EnrollmentTokenActive    = "active"
	EnrollmentTokenExpired   = "expired"
	EnrollmentTokenExhausted = "exhausted"
	EnrollmentTokenRevoked   = "revoked"
)

// EnrollmentToken is a stored organization enrollment token: its keyed hash
// and the presets every sensor it enrolls gets.
type EnrollmentToken struct {
	ID        shared.ID
	TenantID  shared.ID
	Name      string
	TokenHash string
	// TokenHint is the token's last four characters, to tell tokens apart.
	TokenHint       string
	MaxUses         int
	UseCount        int
	RequireApproval bool
	SensorType      SensorType
	GrantProfile    string
	ZoneIDs         []shared.ID
	Labels          map[string]string
	AllowedCIDRs    []netip.Prefix
	CreatedBy       *shared.ID
	CreatedAt       time.Time
	ExpiresAt       time.Time
	LastUsedAt      *time.Time
	LastUsedFrom    net.IP
	RevokedAt       *time.Time
	RevokedBy       *shared.ID
}

// State is what a list shows for the token at now.
func (t *EnrollmentToken) State(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return EnrollmentTokenRevoked
	case !now.Before(t.ExpiresAt):
		return EnrollmentTokenExpired
	case t.UseCount >= t.MaxUses:
		return EnrollmentTokenExhausted
	default:
		return EnrollmentTokenActive
	}
}

// AllowsSource reports whether a request from ip may use the token: any
// address when no range is set, else one inside a range. An unknown address
// never matches a range.
func (t *EnrollmentToken) AllowsSource(ip net.IP) bool {
	if len(t.AllowedCIDRs) == 0 {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range t.AllowedCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// EnrollmentRefusal says why a token could not be used (logged and audited,
// never told to the sensor: it gets one answer for every case).
type EnrollmentRefusal string

const (
	EnrollmentOK            EnrollmentRefusal = ""
	EnrollmentUnknown       EnrollmentRefusal = "unknown"
	EnrollmentRevoked       EnrollmentRefusal = "revoked"
	EnrollmentExpired       EnrollmentRefusal = "expired"
	EnrollmentExhausted     EnrollmentRefusal = "exhausted"
	EnrollmentSourceRefused EnrollmentRefusal = "source_not_allowed"
	EnrollmentCreatorGone   EnrollmentRefusal = "creator_not_a_member"
	EnrollmentKeyBusy       EnrollmentRefusal = "key_has_an_open_request"
)

// EnrollmentTokenRepository stores organization enrollment tokens. Every
// method but the Unscoped ones is scoped by tenant.
type EnrollmentTokenRepository interface {
	CreateEnrollmentToken(ctx context.Context, t *EnrollmentToken) error
	ListEnrollmentTokens(ctx context.Context, tenantID shared.ID, limit int) ([]*EnrollmentToken, error)
	// RevokeEnrollmentToken revokes an unrevoked token of the tenant;
	// ErrPairingNotFound when there is none.
	RevokeEnrollmentToken(ctx context.Context, tenantID, id, by shared.ID, now time.Time) (*EnrollmentToken, error)
	// ZonesInTenant reports whether every id is a scan zone of the tenant.
	ZonesInTenant(ctx context.Context, tenantID shared.ID, ids []shared.ID) (bool, error)
	// StartWithEnrollmentTokenUnscoped finds the token by its hash and, when
	// it may be used (not revoked, not expired, a use left or the same key
	// used it before, the source allowed, its creator still an active
	// member), counts the use and inserts p bound to the token's tenant
	// with its presets, in one transaction. It returns the token (nil when
	// unknown) and why it was refused (EnrollmentOK when p was inserted).
	StartWithEnrollmentTokenUnscoped(ctx context.Context, tokenHash string, p *Pairing, now time.Time) (*EnrollmentToken, EnrollmentRefusal, error)
	// GetEnrollmentTokenUnscoped returns a token by id.
	GetEnrollmentTokenUnscoped(ctx context.Context, id shared.ID) (*EnrollmentToken, error)
	// ListPendingForTenant returns the tenant's open, revealed requests
	// that wait for an administrator (token-bound with require approval, or
	// an expectation the sensor attached to).
	ListPendingForTenant(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]*Pairing, error)
}
