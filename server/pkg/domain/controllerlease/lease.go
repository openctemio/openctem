// Package controllerlease is the named lease a non-idempotent background job
// takes so that it runs on one API replica at a time (RFC-046 §11, B1).
// See docs/rfcs/RFC-046-scans-redesign.md.
package controllerlease

import (
	"context"
	"time"
)

// Lease is one held lease: its name, the process that holds it and the
// epoch it was taken under. Every take of a lease bumps its epoch.
type Lease struct {
	Name   string
	Holder string
	Epoch  int64
}

// Store takes, renews and releases leases. Implemented by
// postgres.ControllerLeaseRepository.
type Store interface {
	// TryAcquire takes name for holder for ttl when it is free (never
	// taken, or expired). ok is false when another holder has it.
	TryAcquire(ctx context.Context, name, holder string, ttl time.Duration) (lease Lease, ok bool, err error)
	// Renew extends a held lease by ttl from now. false: the lease expired
	// and was taken by another holder (or epoch moved on), so the work must
	// stop.
	Renew(ctx context.Context, l Lease, ttl time.Duration) (bool, error)
	// Release gives the lease up at once, if l still holds it.
	Release(ctx context.Context, l Lease) error
}

// MinTTL and MaxTTL bound a lease's time to live.
const (
	MinTTL = 10 * time.Second
	MaxTTL = 24 * time.Hour
)

// ClampTTL returns ttl inside [MinTTL, MaxTTL].
func ClampTTL(ttl time.Duration) time.Duration {
	return min(max(ttl, MinTTL), MaxTTL)
}
