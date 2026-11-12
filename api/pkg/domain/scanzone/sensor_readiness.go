package scanzone

// Plan-time readiness of a zone's sensors (research 466 g, D8): a target is
// not dispatched to a zone whose every sensor would refuse it at claim (a
// New sensor and a job above T0) or on its host (a private target and a
// host that does not allow private targets). The check only narrows what
// the trigger and the dry run send; the claim (the grant) and the sensor
// (its switch and local policy) still decide every job.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ZoneSensorState is what plan-time routing knows about one active sensor
// assigned to a zone, online or not.
type ZoneSensorState struct {
	ID   shared.ID
	Name string
	// Trusted is the sensor's trust level (sensors.trust_level): a New
	// sensor's grant caps it at passive (T0) work.
	Trusted bool
	// LocalPolicy is the sensor's last local policy report (nil: never
	// reported).
	LocalPolicy *sensor.LocalPolicyReport
}

// ZoneSensorStateReader lists the active sensors assigned to each zone, for
// the tenant only. Implemented by postgres.ScanZoneRepository.
type ZoneSensorStateReader interface {
	ZoneSensorStates(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID) (map[shared.ID][]ZoneSensorState, error)
}

// TierUnknown is a job tier the platform cannot tell before the claim (a
// tool it does not know): the trust check is left to the claim.
const TierUnknown = -1

// SensorNeed is what one job asks of a zone's sensors.
type SensorNeed struct {
	// Tier is the job's tier as the grant rates it (0 passive, 1 active, 2
	// intrusive), or TierUnknown.
	Tier int
	// Private: the job names a private address (RFC1918, IPv6 ULA).
	Private bool
	// SensorID, when set, is the one sensor the job is pinned to.
	SensorID *shared.ID
}

// SensorVerdict is the outcome of JudgeZoneSensors.
type SensorVerdict struct {
	// Eligible are the sensors that may take the job (nil: no state was
	// given, nothing is decided here).
	Eligible map[shared.ID]bool
	// Kind is KindZoneSensorNew or KindZoneSensorNoPrivate when no sensor
	// is eligible; "" otherwise.
	Kind string
	// Reason explains Kind, naming the zone and the sensors.
	Reason string
	// SensorID is the sensor the fix acts on (the first refusing one).
	SensorID shared.ID
}

// maxNamedZoneSensors bounds the sensor names a reason lists.
const maxNamedZoneSensors = 3

// JudgeZoneSensors decides which of a zone's sensors may take a job. The
// trust check comes first (a New sensor and a job above T0), then the
// private check (a private target and a host that refuses private targets).
// With no sensor state, or a pinned sensor that is not among them, nothing
// is decided (the zone checks that exist already answer those cases).
func JudgeZoneSensors(zone *Zone, states []ZoneSensorState, need SensorNeed) SensorVerdict {
	if need.SensorID != nil {
		var pinned []ZoneSensorState
		for _, st := range states {
			if st.ID == *need.SensorID {
				pinned = append(pinned, st)
			}
		}
		states = pinned
	}
	if len(states) == 0 {
		return SensorVerdict{}
	}
	name := ""
	if zone != nil {
		name = zone.Name
	}
	trusted := states
	if need.Tier > 0 {
		trusted = nil
		for _, st := range states {
			if st.Trusted {
				trusted = append(trusted, st)
			}
		}
		if len(trusted) == 0 {
			return SensorVerdict{Kind: KindZoneSensorNew, SensorID: states[0].ID, Reason: fmt.Sprintf(
				"every sensor of scan zone %q is New and runs passive (T0) work only, and this job is T%d; trust %s to run it",
				name, need.Tier, namesOf(states))}
		}
	}
	ok := trusted
	if need.Private {
		ok = nil
		var refusing []ZoneSensorState
		for _, st := range trusted {
			if st.LocalPolicy.RefusesPrivate() {
				refusing = append(refusing, st)
				continue
			}
			ok = append(ok, st)
		}
		if len(ok) == 0 {
			return SensorVerdict{Kind: KindZoneSensorNoPrivate, SensorID: refusing[0].ID, Reason: fmt.Sprintf(
				"no sensor of scan zone %q that could run this job allows private targets on its host (%s); %s",
				name, namesOf(refusing), sensor.PrivateTargetsHostHint)}
		}
	}
	v := SensorVerdict{Eligible: make(map[shared.ID]bool, len(ok))}
	for _, st := range ok {
		v.Eligible[st.ID] = true
	}
	return v
}

// namesOf lists sensor names for a reason: "sensor "a"", "sensors "a" and
// "b"", with at most maxNamedZoneSensors named.
func namesOf(states []ZoneSensorState) string {
	q := make([]string, 0, maxNamedZoneSensors)
	for _, st := range states {
		if len(q) == maxNamedZoneSensors {
			break
		}
		q = append(q, fmt.Sprintf("%q", st.Name))
	}
	more := ""
	if n := len(states) - len(q); n > 0 {
		more = fmt.Sprintf(" and %d more", n)
	}
	if len(q) == 1 && more == "" {
		return "sensor " + q[0]
	}
	if more != "" {
		return "sensors " + strings.Join(q, ", ") + more
	}
	return "sensors " + strings.Join(q[:len(q)-1], ", ") + " and " + q[len(q)-1]
}

// RoutePrivate reports whether a routed target is a private address
// (RFC1918, IPv6 ULA: what a sensor's private-range switch governs): a
// private address or range, or a hostname that resolved to one.
func RoutePrivate(rt Route) bool {
	if pt := ParseTarget(rt.Target); pt.IsAddr {
		return pt.Prefix.Addr().IsPrivate()
	}
	for _, a := range rt.Addrs {
		if a.Unmap().IsPrivate() {
			return true
		}
	}
	return false
}
