package command

// Placement: why a queued command waits (docs/architecture/placement.md).
//
// The claim predicates in the command repository decide which sensor may
// take a command; the placement explainer reads the same predicates back
// for one command and every sensor of its tenant, so a queued task can say
// why it waits and what would fix it.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Job-level placement reasons: they hold the command whatever the sensor.
const (
	// PlacementExpired: the command expired before a sensor took it.
	PlacementExpired = "expired"
	// PlacementWindowClosed: the command waits for its scan window (it is
	// scheduled for the window's next opening).
	PlacementWindowClosed = "window_closed"
	// PlacementHostBusy: another task of the organization is scanning one
	// of the command's hosts; it starts when that one ends.
	PlacementHostBusy = "host_busy"
)

// Sensor-level placement reasons, in the order the explainer checks them.
const (
	// PlacementInactive: the sensor is disabled or revoked.
	PlacementInactive = "inactive"
	// PlacementOffline: the sensor has not checked in recently.
	PlacementOffline = "offline"
	// PlacementPinnedElsewhere: the command is reserved for another sensor.
	PlacementPinnedElsewhere = "pinned_elsewhere"
	// PlacementRefusedEarlier: the sensor already refused this command.
	PlacementRefusedEarlier = "refused_earlier"
	// PlacementOutsideZone: the command belongs to a scan zone the sensor
	// is not assigned to (or the sensor in the zone lacks the tool).
	PlacementOutsideZone = "outside_zone"
	// PlacementToolMissing: the sensor did not report the command's tool
	// as installed.
	PlacementToolMissing = "tool_missing"
	// PlacementCapabilityMissing: the sensor does not offer a capability
	// the command requires.
	PlacementCapabilityMissing = "capability_missing"
	// PlacementNotConfined: the command needs network confinement
	// (PayloadKeyRequiredFeatures) and the sensor did not report it.
	PlacementNotConfined = "not_confined"
	// PlacementGrantPrefix prefixes a refusal by the sensor's grant:
	// "grant_" + the grant dimension (job_types, zones, tools, tier, ...).
	PlacementGrantPrefix = "grant_"
	// PlacementIntensity: on this sensor the job's tier is above the
	// scan's intensity.
	PlacementIntensity = "intensity"
	// PlacementPolicyUnavailable: the sensor's grant or policy could not be
	// read; nothing is dispatched to it until it can (fail closed).
	PlacementPolicyUnavailable = "policy_unavailable"
	// PlacementPrivateNeedsPolicy: the command has private targets, the
	// organization requires a sensor-local policy for them, and the sensor
	// reports none.
	PlacementPrivateNeedsPolicy = "private_needs_local_policy"
	// PlacementOptInDisabled: the command asks for an opt-in (out-of-band
	// callbacks, custom templates) the organization has not enabled.
	PlacementOptInDisabled = "opt_in_disabled"
	// PlacementLocalPolicy: the sensor's own local policy refuses the
	// command.
	PlacementLocalPolicy = "local_policy_refuses"
	// PlacementNoFreeSlot: the sensor could take the command but runs as
	// many scans as it can now.
	PlacementNoFreeSlot = "no_free_slot"
)

// PayloadKeyRequiredFeatures lists what a sensor must enforce to take the
// command (today only sensor.CapabilityNetConfined): matched against the
// capabilities the sensor itself reported, never against an
// administrator's list. Kept apart from the signed job's statement fields.
const PayloadKeyRequiredFeatures = "required_features"

// PlacementJob is the job-level half of the claim predicates for one
// command, as the repository evaluates them.
type PlacementJob struct {
	Status        CommandStatus
	IsPlatformJob bool
	NotExpired    bool
	Due           bool
	HostFree      bool
}

// SensorClaim is the per-sensor half of the claim predicates for one
// command and one sensor of its tenant, as the repository evaluates them,
// with the scans the sensor holds now.
type SensorClaim struct {
	SensorID     shared.ID
	PinOK        bool
	ZoneOK       bool
	ToolOK       bool
	NotRefused   bool
	CapabilityOK bool
	FeaturesOK   bool
	HeldScans    int
}

// PlacementReader evaluates the claim predicates of one command of the
// tenant against at most maxSensors of the tenant's sensors (by name).
// A command of another tenant is shared.ErrNotFound.
type PlacementReader interface {
	PlacementPredicates(ctx context.Context, tenantID, commandID shared.ID, maxSensors int) (PlacementJob, []SensorClaim, error)
}
