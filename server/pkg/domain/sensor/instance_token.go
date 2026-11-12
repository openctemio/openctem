package sensor

// Instance enrollment tokens (docs/rfcs/RFC-100-shared-sensors.md §7): a
// super administrator issues a single-use token, valid at most one hour; a
// sensor that starts pairing with it becomes a shared sensor.

import (
	"net"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxInstanceTokenTTL is the longest an instance enrollment token lives.
const MaxInstanceTokenTTL = time.Hour

// InstanceEnrollmentToken is a stored token: only its peppered hash.
type InstanceEnrollmentToken struct {
	ID        shared.ID
	TokenHash string
	Name      string
	Reason    string
	// CreatedBy is the administrator who issued it (nil when issued by the
	// install's bootstrap tool, or when the administrator was deleted).
	CreatedBy      *shared.ID
	CreatedByEmail string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	UsedAt         *time.Time
	UsedFrom       net.IP
}

// InstanceApproval is what approving a token-bound request writes, in one
// transaction: a sensor of scope instance (no tenant; the insert trigger
// gives it trust level trusted and the least-privilege grant) and its key.
type InstanceApproval struct {
	PairingID shared.ID
	Now       time.Time
	ConfirmBy time.Time
	SensorID  shared.ID
	KeyID     shared.ID
	Name      string
	Type      SensorType
	Hostname  string
	OS, Arch  string
	Version   string
}
