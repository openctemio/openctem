package command

// Claim balance across an organization's sensors
// (docs/architecture/placement.md, "Spreading work across sensors").
//
// Work is pulled: every eligible sensor is woken when a job is queued and the
// first claim wins. Without more, the sensor that answers fastest (lowest
// round trip, or the one that just finished the previous stage and polls
// again at once) takes every job up to its free slots while an idle peer gets
// nothing. The claim therefore looks at the peers that could take the same
// fresh jobs and leaves them the share a least-loaded-first placement would
// give them. A job is left only for a short window after it became
// claimable; after that any eligible sensor takes it, so a peer that does not
// claim (stopped, refusing for a reason the SQL cannot see) delays work by at
// most that window and never starves it.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DefaultClaimBalanceWindow is how long after a job became claimable a
// busier sensor leaves it to a less-loaded peer. Long enough for a woken
// peer to claim (milliseconds on a control stream, one busy interval when
// polling), short enough that a peer that never claims costs little.
const DefaultClaimBalanceWindow = 10 * time.Second

// ClaimBalanceRecent is the period whose claims count as a sensor's recent
// load: the tie-break between sensors with the same share of free slots, so
// one-job stages do not always go to the fastest sensor.
const ClaimBalanceRecent = 15 * time.Minute

// SensorLoad is a sensor's load at claim time.
type SensorLoad struct {
	// Free is the scan slots it may still fill (Sensor.FreeSlots rule).
	Free int
	// Total is its effective job limit (at least 1).
	Total int
	// Recent is the commands it claimed in the last ClaimBalanceRecent.
	Recent int
}

// LessLoaded reports whether a should take the next job before b: the
// larger share of free slots first, then the fewer recent claims. Equal
// loads are not less loaded (the caller keeps its own order).
func (a SensorLoad) LessLoaded(b SensorLoad) bool {
	// a.Free/a.Total > b.Free/b.Total, without division.
	l, r := a.Free*max(b.Total, 1), b.Free*max(a.Total, 1)
	if l != r {
		return l > r
	}
	return a.Recent < b.Recent
}

// ContestedCommand is a fresh unassigned scan command the claiming sensor
// may take that other sensors of the tenant could take now too.
type ContestedCommand struct {
	ID shared.ID
	// Peers are the other sensors that pass the command's claim predicates
	// and have a free slot.
	Peers []shared.ID
}

// ClaimContest is what a claim needs to leave peers their share.
type ClaimContest struct {
	// SelfRecent is the claiming sensor's recent claims.
	SelfRecent int
	// Peers is the load of every peer named in Commands.
	Peers map[shared.ID]SensorLoad
	// Commands are the contested commands, oldest first.
	Commands []ContestedCommand
}

// ClaimContester reads a claim's contest. Optional extension of Repository,
// asserted by the command service.
type ClaimContester interface {
	// ClaimContest returns, for a claim by sensorID in tenantID, the
	// unassigned pending scan commands that became claimable within window,
	// pass the sensor's claim predicates (capabilities as the claim's) and
	// that at least one other active, reachable organization sensor of the
	// same tenant with a free slot could claim too; at most limit. Sensors
	// of other tenants and shared sensors never count.
	ClaimContest(ctx context.Context, tenantID, sensorID shared.ID, capabilities []string, window time.Duration, limit int) (ClaimContest, error)

	// SensorLoads returns the load of the given sensors of tenantID (others
	// are left out).
	SensorLoads(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]SensorLoad, error)
}
