package sensor

// The heartbeat doorbell (RFC-023 §9.2a): the heartbeat response tells a
// sensor THAT something is waiting for it, never WHAT. Jobs are still fetched
// and claimed through the command poll, so authorization, the zone claim
// predicate and claim semantics stay in one place.

// Action is a typed control directive the platform can ring on the heartbeat
// (RFC-023 §10.2 K1). The set is closed: a sensor must ignore a value it does
// not know, and there is no free-form or shell verb (RFC-023 §10.4 R-4).
type Action string

const (
	// ActionPause: stop taking new jobs until a heartbeat no longer carries
	// pause. Rung while an administrator has the sensor disabled.
	ActionPause Action = "pause"
	// ActionResume: reserved. A sensor resumes on the first heartbeat without
	// pause; the platform keeps no per-sensor "was paused" state to ring it.
	ActionResume Action = "resume"
	// ActionDrain: reserved. Finish running jobs, take no new ones.
	ActionDrain Action = "drain"
	// ActionRotateKey: the presented key is inside its renewal window; call
	// POST /api/v2/sensor/keys.
	ActionRotateKey Action = "rotate_key"
	// ActionUpdate: reserved. A newer sensor release is required.
	ActionUpdate Action = "update"
)

// Actions lists every action the protocol defines, in wire order.
func Actions() []Action {
	return []Action{ActionPause, ActionResume, ActionDrain, ActionRotateKey, ActionUpdate}
}

// IsValid reports whether a is one of the defined actions.
func (a Action) IsValid() bool {
	switch a {
	case ActionPause, ActionResume, ActionDrain, ActionRotateKey, ActionUpdate:
		return true
	}
	return false
}

// PendingWork is what the doorbell reads from the command queue for one
// sensor in a single query.
type PendingWork struct {
	// Count is how many pending commands the sensor could claim right now,
	// capped at the limit the query was given.
	Count int
	// ZoneFingerprint identifies the sensor's zone assignments and each
	// zone's last change; it feeds the config version.
	ZoneFingerprint string
	// RecentlyCanceled is how many commands this sensor had claimed that
	// were canceled within the last lease period, capped like Count. The
	// sensor may still be running them, so it is asked to ring again soon
	// and learns the cancel (cancel_command_ids) within seconds, not after
	// an idle interval.
	RecentlyCanceled int
}

// HeartbeatHints is the doorbell part of a heartbeat response. Zero values
// mean "nothing to say" and are omitted on the wire.
type HeartbeatHints struct {
	PendingJobs          int
	ConfigVersion        string
	Actions              []Action
	NextHeartbeatSeconds int
}
