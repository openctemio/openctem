// Package verifieddomain is the domain model for tenant-scoped DNS-TXT
// domain-ownership verification. A verified row proves a tenant controls an
// email domain and is the trust boundary that gates SSO JIT auto-provisioning.
package verifieddomain

import (
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Status is the verification lifecycle state of a domain.
type Status string

const (
	// StatusPending — the TXT record has not yet been observed.
	StatusPending Status = "pending"
	// StatusVerified — the expected TXT record was observed; the tenant owns it.
	StatusVerified Status = "verified"
	// StatusFailed — a previously verified record disappeared (lapsed/hijacked),
	// or verification was explicitly abandoned. Fail-closed: no JIT authority.
	StatusFailed Status = "failed"
)

// IsValid reports whether s is a known status.
func (s Status) IsValid() bool {
	switch s {
	case StatusPending, StatusVerified, StatusFailed:
		return true
	}
	return false
}

// VerifiedDomain is a tenant's claim over an email domain, proven via DNS TXT.
type VerifiedDomain struct {
	id                shared.ID
	tenantID          shared.ID
	domain            string
	verificationToken string
	status            Status
	verifiedAt        *time.Time
	lastCheckedAt     *time.Time
	createdAt         time.Time
	updatedAt         time.Time
}

// New creates a pending VerifiedDomain. The domain is normalized and validated;
// callers must supply a non-empty verification token. It does NOT enforce the
// shared/public-domain blocklist — that policy lives in the service layer.
func New(id, tenantID shared.ID, domain, token string) (*VerifiedDomain, error) {
	normalized, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, ErrInvalidDomain
	}
	now := time.Now().UTC()
	return &VerifiedDomain{
		id:                id,
		tenantID:          tenantID,
		domain:            normalized,
		verificationToken: token,
		status:            StatusPending,
		createdAt:         now,
		updatedAt:         now,
	}, nil
}

// Reconstruct rebuilds a VerifiedDomain from persistence without validation.
func Reconstruct(
	id, tenantID shared.ID,
	domain, token string,
	status Status,
	verifiedAt, lastCheckedAt *time.Time,
	createdAt, updatedAt time.Time,
) *VerifiedDomain {
	return &VerifiedDomain{
		id:                id,
		tenantID:          tenantID,
		domain:            domain,
		verificationToken: token,
		status:            status,
		verifiedAt:        verifiedAt,
		lastCheckedAt:     lastCheckedAt,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
	}
}

// Getters.
func (d *VerifiedDomain) ID() shared.ID             { return d.id }
func (d *VerifiedDomain) TenantID() shared.ID       { return d.tenantID }
func (d *VerifiedDomain) Domain() string            { return d.domain }
func (d *VerifiedDomain) VerificationToken() string { return d.verificationToken }
func (d *VerifiedDomain) Status() Status            { return d.status }
func (d *VerifiedDomain) VerifiedAt() *time.Time    { return d.verifiedAt }
func (d *VerifiedDomain) LastCheckedAt() *time.Time { return d.lastCheckedAt }
func (d *VerifiedDomain) CreatedAt() time.Time      { return d.createdAt }
func (d *VerifiedDomain) UpdatedAt() time.Time      { return d.updatedAt }
func (d *VerifiedDomain) IsVerified() bool          { return d.status == StatusVerified }

// MarkVerified stamps the domain as verified at t and records the check time.
func (d *VerifiedDomain) MarkVerified(t time.Time) {
	t = t.UTC()
	d.status = StatusVerified
	d.verifiedAt = &t
	d.lastCheckedAt = &t
	d.updatedAt = t
}

// MarkChecked records that a verification attempt ran at t without success. A
// still-pending domain stays pending; a previously verified domain whose record
// vanished is downgraded to failed (fail-closed). Never promotes to verified.
func (d *VerifiedDomain) MarkChecked(t time.Time) {
	t = t.UTC()
	if d.status == StatusVerified {
		d.status = StatusFailed
	}
	d.lastCheckedAt = &t
	d.updatedAt = t
}

// NormalizeDomain lowercases, trims, strips a trailing dot / leading "@", and
// validates the shape of a DNS domain name. It rejects wildcards, whitespace,
// schemes, and paths so a domain claim is an exact hostname.
func NormalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "@")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return "", ErrInvalidDomain
	}
	if strings.ContainsAny(d, " \t\r\n/\\*:@") {
		return "", ErrInvalidDomain
	}
	// Must be a multi-label name (contain at least one dot) with valid labels.
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", ErrInvalidDomain
	}
	for _, label := range labels {
		if !validLabel(label) {
			return "", ErrInvalidDomain
		}
	}
	return d, nil
}

// validLabel reports whether a single DNS label is well-formed:
// 1..63 chars of [a-z0-9-], not starting or ending with a hyphen.
func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
			return false
		}
	}
	return true
}
