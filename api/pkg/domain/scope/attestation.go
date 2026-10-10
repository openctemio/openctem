package scope

// Re-attestation of long intrusive (t2) entries (RFC-054 §12.5).
//
// An active t2 entry whose life runs past its next attestation (a permanent
// one, or one expiring after it) is confirmed every attestation interval
// (the tenant's t2_attestation_days) from its approval or last attestation.
// When an attestation falls due the owners and administrators are asked
// "keep T2?"; an answer starts the next period; no answer within
// AttestationGrace downgrades the entry to t1. It is never deleted, and
// raising it back to t2 is an ordinary widening.

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AttestationGrace is how long a requested attestation waits for an answer
// before the entry falls back to t1.
const AttestationGrace = 14 * 24 * time.Hour

// Attestation errors.
var ErrNotIntrusive = shared.NewDomainError("ENTRY_NOT_INTRUSIVE",
	"only an active t2 (intrusive) entry is attested", shared.ErrConflict)

// AttestationState is the persisted attestation part of an entry.
type AttestationState struct {
	AttestedAt  *time.Time
	AttestedBy  string
	RequestedAt *time.Time
}

// RestoreAttestation sets the attestation fields read from persistence.
func (t *Target) RestoreAttestation(a AttestationState) {
	t.attestedAt, t.attestedBy, t.attestationRequestedAt = a.AttestedAt, a.AttestedBy, a.RequestedAt
}

// Attestation getters.
func (t *Target) AttestedAt() *time.Time             { return t.attestedAt }
func (t *Target) AttestedBy() string                 { return t.attestedBy }
func (t *Target) AttestationRequestedAt() *time.Time { return t.attestationRequestedAt }

// AttestationDueAt is when the entry's next attestation falls due, or nil
// when it needs none: not an active t2 entry, or it expires first. The
// period starts at the later of the approval and the last attestation.
func (t *Target) AttestationDueAt(interval time.Duration) *time.Time {
	if t.maxTier != TierIntrusive || t.status != StatusActive || interval <= 0 {
		return nil
	}
	base := t.createdAt
	if t.approvedAt != nil && t.approvedAt.After(base) {
		base = *t.approvedAt
	}
	if t.attestedAt != nil && t.attestedAt.After(base) {
		base = *t.attestedAt
	}
	due := base.Add(interval)
	if t.expiresAt != nil && !due.Before(*t.expiresAt) {
		return nil
	}
	return &due
}

// DowngradeAt is when an unanswered attestation request downgrades the entry
// (nil: no request open).
func (t *Target) DowngradeAt() *time.Time {
	if t.attestationRequestedAt == nil || t.maxTier != TierIntrusive {
		return nil
	}
	at := t.attestationRequestedAt.Add(AttestationGrace)
	return &at
}

// Attest confirms that the entry keeps t2 and starts the next period.
func (t *Target) Attest(userID string, now time.Time) error {
	if userID == "" {
		return fmt.Errorf("%w: a person attests", shared.ErrValidation)
	}
	if t.maxTier != TierIntrusive || !t.InEffect(now) {
		return ErrNotIntrusive
	}
	t.attestedAt, t.attestedBy, t.attestationRequestedAt = &now, userID, nil
	t.updatedAt = now
	return nil
}
