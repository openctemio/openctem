// Package idempotency is the durable Idempotency-Key store
// (docs/rfcs/RFC-122-ingest-receipts.md §6).
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Header is the request header that carries the key.
const Header = "Idempotency-Key"

// MaxKeyLen bounds the key a client sends.
const MaxKeyLen = 128

// TTL is how long a completed answer is replayable.
const TTL = 24 * time.Hour

// MaxResponse bounds a stored answer.
const MaxResponse = 1 << 20

// States.
const (
	StatePending = "pending"
	StateDone    = "done"
)

// ErrInvalidKey is a key that is empty, too long or not printable ASCII.
var ErrInvalidKey = errors.New("Idempotency-Key must be 1 to 128 printable ASCII characters")

// Scope names one key: the tenant, the principal behind the request
// ("user:<id>" or "key:<id>"), the route and the SHA-256 of the key.
type Scope struct {
	TenantID  shared.ID
	Principal string
	Route     string
	KeyHash   string
}

// NewScope validates key and builds its scope.
func NewScope(tenantID shared.ID, principal, route, key string) (Scope, error) {
	if key == "" || len(key) > MaxKeyLen {
		return Scope{}, ErrInvalidKey
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return Scope{}, ErrInvalidKey
		}
	}
	sum := sha256.Sum256([]byte(key))
	return Scope{TenantID: tenantID, Principal: principal, Route: route, KeyHash: hex.EncodeToString(sum[:])}, nil
}

// Record is a stored key.
type Record struct {
	State         string
	RequestSHA256 string
	Status        int
	Response      []byte
	ReceiptID     *shared.ID
	ExpiresAt     time.Time
}

// Claim is a request's hold on a pending key.
type Claim struct {
	Scope Scope
	Token shared.ID
}

// Store is the durable key store. Every method is scoped by tenant.
type Store interface {
	// Claim takes the key for this request (a new key, or an expired one).
	// When another unexpired record holds it, claim is nil and existing is
	// that record.
	Claim(ctx context.Context, s Scope, pendingFor time.Duration) (claim *Claim, existing *Record, err error)
	// Complete stores the answer of the claimed request; ErrNotFound when the
	// claim was lost (the key expired and was taken over).
	Complete(ctx context.Context, c *Claim, fingerprint string, status int, response []byte, receiptID *shared.ID) error
	// Release gives the key up after a failure, so a retry runs again.
	Release(ctx context.Context, c *Claim) error
}
