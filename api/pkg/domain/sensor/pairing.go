package sensor

// Interactive pairing (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4): a sensor that holds only the platform URL asks to pair with its own
// key; an administrator approves it after comparing the SAS fingerprint.

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PairingMode is who shows the code.
type PairingMode string

const (
	// PairingForward: the sensor starts and shows a code the administrator
	// enters (the default).
	PairingForward PairingMode = "forward"
	// PairingReverse: the administrator expects a sensor and gets a code
	// the operator gives the sensor.
	PairingReverse PairingMode = "reverse"
)

// PairingStatus is the state of a pairing row.
type PairingStatus string

const (
	PairingExpecting PairingStatus = "expecting"
	PairingPending   PairingStatus = "pending"
	PairingApproved  PairingStatus = "approved"
	PairingCompleted PairingStatus = "completed"
	PairingDenied    PairingStatus = "denied"
	PairingExpired   PairingStatus = "expired"
)

// Pairing errors. ErrPairingNotFound is the one answer for unknown,
// expired, used, denied and foreign requests (RFC-052 §4.4).
var (
	ErrPairingNotFound = errors.New("pairing not found")
	// ErrPairingCapacity: too many open requests platform-wide.
	ErrPairingCapacity = errors.New("too many open pairing requests")
)

// PairingHostFacts are the host facts a sensor reported, bounded and
// sanitized before they are stored (claims, shown to the approver).
type PairingHostFacts struct {
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	SensorVersion string `json:"sensor_version,omitempty"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	Product       string `json:"product,omitempty"`
	InstanceID    string `json:"instance_id,omitempty"`
	Name          string `json:"name,omitempty"`
}

// Pairing is one pairing request.
type Pairing struct {
	ID       shared.ID
	Mode     PairingMode
	Status   PairingStatus
	TenantID *shared.ID
	CodeHash string

	PublicKey     []byte
	Thumbprint    string
	Commitment    []byte
	SensorNonce   []byte
	PlatformNonce []byte
	SAS           string

	HostFacts PairingHostFacts
	SourceIP  net.IP

	RepairSensorID *shared.ID
	SensorID       *shared.ID

	RequestedName    string
	RequestedZoneIDs []shared.ID
	RequestedProfile string

	CreatedBy   *shared.ID
	ApprovedBy  *shared.ID
	ApprovedAt  *time.Time
	DeniedBy    *shared.ID
	DeniedAt    *time.Time
	ConfirmedAt *time.Time
	CreatedAt   time.Time
	ExpiresAt   time.Time

	// InstanceTokenID is the instance enrollment token the sensor started
	// with: such a request never has a tenant and approves a shared sensor.
	InstanceTokenID *shared.ID
	// EnrollmentTokenID is the organization enrollment token the sensor
	// started with: the request has the token's tenant from the start.
	EnrollmentTokenID *shared.ID
}

// IsInstance reports whether the request enrolls a shared sensor.
func (p *Pairing) IsInstance() bool { return p != nil && p.InstanceTokenID != nil }

// IsEnrollment reports whether an organization enrollment token started the
// request.
func (p *Pairing) IsEnrollment() bool { return p != nil && p.EnrollmentTokenID != nil }

// Revealed reports whether the sensor revealed its nonce (the SAS exists).
func (p *Pairing) Revealed() bool { return p != nil && len(p.SensorNonce) > 0 && p.SAS != "" }

// PairingApproval is what an approval writes, in one transaction.
type PairingApproval struct {
	PairingID shared.ID
	// CodeHash must match a tenantless (default-mode) request: approving
	// needs the code, never the id alone.
	CodeHash   string
	TenantID   shared.ID
	ApprovedBy shared.ID
	Now        time.Time
	// ConfirmBy is when the sensor's confirmation window closes.
	ConfirmBy time.Time
	// New sensor (ignored on re-pair).
	SensorID shared.ID
	Name     string
	Type     SensorType
	Hostname string
	OS, Arch string
	Version  string
	ZoneIDs  []shared.ID
	KeyID    shared.ID
	// OnApproved runs inside the approval transaction once the sensor
	// exists (the grant is created here); an error rolls everything back.
	OnApproved func(ctx context.Context, tx *sql.Tx, sensorID shared.ID, repair bool) error
}

// PairingApprovalResult is the outcome of an approval.
type PairingApprovalResult struct {
	Pairing  *Pairing
	SensorID shared.ID
	Repair   bool
	// RevokedKeys is how many earlier keys a re-pair revoked.
	RevokedKeys int64
}

// PairingRepository stores pairing requests. Methods named Unscoped work on
// rows that may have no tenant yet (the sensor plane); they are called only
// by the pairing service.
type PairingRepository interface {
	CountOpenUnscoped(ctx context.Context, now time.Time) (int, error)
	CreateForward(ctx context.Context, p *Pairing) error
	// AttachToExpectationUnscoped fills an open expectation whose code hash
	// matches with the sensor's key and nonces; false when none matches.
	AttachToExpectationUnscoped(ctx context.Context, codeHash string, p *Pairing, now time.Time) (bool, error)
	// KeyRegisteredUnscoped reports whether the key was ever registered to
	// a sensor (sensor_keys, any status or tenant).
	KeyRegisteredUnscoped(ctx context.Context, thumbprint string) (bool, error)
	// SupersedeForKeyUnscoped closes the key's open, unapproved requests
	// (expired) except its own reverse-mode request under keepCodeHash that
	// is still open, and returns the closed ones.
	SupersedeForKeyUnscoped(ctx context.Context, thumbprint, keepCodeHash string, now time.Time) ([]*Pairing, error)
	GetForKeyUnscoped(ctx context.Context, id shared.ID, thumbprint string) (*Pairing, error)
	RevealUnscoped(ctx context.Context, id shared.ID, thumbprint string, sensorNonce []byte, sas string, now time.Time) (bool, error)
	// FindOpenByCodeHash returns the open, revealed default-mode request
	// with this code (no tenant yet).
	FindOpenByCodeHash(ctx context.Context, codeHash string, now time.Time) (*Pairing, error)
	// FindOpenForTenantByCodeHash returns the tenant's open, revealed
	// reverse-mode request with this code (a sensor attached to it).
	FindOpenForTenantByCodeHash(ctx context.Context, tenantID shared.ID, codeHash string, now time.Time) (*Pairing, error)
	// ExpireStaleCodeUnscoped closes the open rows of this code whose
	// expiry passed, so the code can open a new request.
	ExpireStaleCodeUnscoped(ctx context.Context, codeHash string, now time.Time) error
	CreateExpectation(ctx context.Context, p *Pairing) error
	GetForTenant(ctx context.Context, tenantID, id shared.ID) (*Pairing, error)
	Approve(ctx context.Context, a PairingApproval, repair *shared.ID) (*PairingApprovalResult, error)
	// Deny refuses an open request of the tenant, or a tenantless
	// default-mode request whose code hash is codeHash (never with an empty
	// hash).
	Deny(ctx context.Context, tenantID, id, actor shared.ID, codeHash string, now time.Time) (*Pairing, error)
	ConfirmUnscoped(ctx context.Context, id shared.ID, thumbprint string, now time.Time) (*Pairing, error)
	// ExpireForPlatform marks requests past their expiry expired and purges
	// rows older than purgeBefore; it revokes the pending key of an approval
	// that was never confirmed.
	ExpireForPlatform(ctx context.Context, now, purgeBefore time.Time) (int64, error)

	// CreateInstanceToken stores a new instance enrollment token (its hash).
	CreateInstanceToken(ctx context.Context, t *InstanceEnrollmentToken) error
	// StartWithInstanceTokenUnscoped spends the unused, unexpired token with
	// this hash and inserts p bound to it, in one transaction; false (and
	// nothing written) when no such token exists.
	StartWithInstanceTokenUnscoped(ctx context.Context, tokenHash string, p *Pairing, now time.Time) (*InstanceEnrollmentToken, bool, error)
	// GetInstanceTokenUnscoped returns a token by id.
	GetInstanceTokenUnscoped(ctx context.Context, id shared.ID) (*InstanceEnrollmentToken, error)
	// ApproveInstanceUnscoped approves a revealed request bound to an
	// instance token: a shared sensor (no tenant) and its pending key.
	ApproveInstanceUnscoped(ctx context.Context, a InstanceApproval) (*PairingApprovalResult, error)
}
