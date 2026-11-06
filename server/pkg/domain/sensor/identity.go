package sensor

// Cloned-identity signal for key-authenticated sensors
// (docs/rfcs/RFC-032-sensor-enrollment-and-identity.md, E13 for `rda_` keys).
//
// Every sensor process picks a random instance id at start and sends it on
// each heartbeat. A restart replaces the id once and the old one is never
// seen again. When one key runs in two places (a copied key, two replicas
// sharing one key) the ids alternate: an id that was replaced comes back.
// Coming back a few times within the window is the signal; a single return
// (a restart whose last heartbeat of the old process lands after the first
// heartbeat of the new one) is not.

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"time"
)

// Clone detection limits.
const (
	// CloneWindow is how long an instance stays "live" after its last
	// heartbeat. It covers the longest advised heartbeat interval (5 min) twice
	// over, so two copies on the slowest schedule still alternate inside it.
	CloneWindow = 15 * time.Minute
	// CloneReturnThreshold is how many returns of a replaced instance within
	// CloneWindow flag the identity as cloned.
	CloneReturnThreshold = 3
	// MaxInstanceIDLength bounds the reported instance id.
	MaxInstanceIDLength = 64
	// maxTrackedInstances bounds the state stored per sensor.
	maxTrackedInstances = 8
	// hostInstancePrefix marks an instance derived from the hostname, for
	// sensors whose SDK does not send an instance id.
	hostInstancePrefix = "host:"
)

// InstanceState is what the platform remembers about the processes that
// used a sensor's key recently. Stored as JSON on the sensor row.
type InstanceState struct {
	// Current is the instance of the last heartbeat that changed the instance.
	Current string `json:"current,omitempty"`
	// Seen maps each recently seen instance to its last heartbeat. The
	// current instance's entry is written when it is replaced (heartbeats of
	// an unchanged instance write nothing).
	Seen map[string]time.Time `json:"seen,omitempty"`
	// Returns are the times a replaced instance heartbeated again.
	Returns []time.Time `json:"returns,omitempty"`
}

// InstanceVerdict is what one observation concluded.
type InstanceVerdict struct {
	// Changed is true when the heartbeat came from another instance than the
	// current one.
	Changed bool
	// Returned is true when that instance had been replaced within the window.
	Returned bool
	// Cloned is true when the returns within the window reach the threshold.
	Cloned bool
	// Live lists the instances seen within the window, sorted.
	Live []string
}

// SanitizeInstanceID returns the reported instance id when it is a plausible
// token (letters, digits, '-', '_', '.', at most MaxInstanceIDLength), else "".
func SanitizeInstanceID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxInstanceIDLength {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return s
}

// HeartbeatInstance is the instance a heartbeat stands for: the reported
// instance id when there is one, else one derived from the hostname (older
// SDKs send no instance id; a recreated container or pod has a new
// hostname, a copied key on another machine a different one). "" when the
// heartbeat carries neither, and then nothing is observed.
func HeartbeatInstance(instanceID, hostname string) string {
	if id := SanitizeInstanceID(instanceID); id != "" {
		return id
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(hostname))
	return hostInstancePrefix + hex.EncodeToString(sum[:8])
}

// Observe records a heartbeat from instance id at now. currentLastSeen is
// the last heartbeat of the current instance (the sensor's last-seen time):
// it is written for the current instance when id replaces it. The receiver
// is not modified.
func (st InstanceState) Observe(id string, now, currentLastSeen time.Time) (InstanceState, InstanceVerdict) {
	next := InstanceState{Current: st.Current, Seen: maps.Clone(st.Seen), Returns: nil}
	if next.Seen == nil {
		next.Seen = map[string]time.Time{}
	}
	cutoff := now.Add(-CloneWindow)
	for _, t := range st.Returns {
		if t.After(cutoff) {
			next.Returns = append(next.Returns, t)
		}
	}

	var v InstanceVerdict
	if id != st.Current {
		v.Changed = true
		if st.Current != "" {
			last := currentLastSeen
			if prev, ok := next.Seen[st.Current]; ok && prev.After(last) {
				last = prev
			}
			if !last.IsZero() {
				next.Seen[st.Current] = last
			}
		}
		if prev, ok := next.Seen[id]; ok && prev.After(cutoff) && st.Current != "" {
			v.Returned = true
			next.Returns = append(next.Returns, now)
		}
		next.Current = id
	}
	next.Seen[id] = now

	for k, t := range next.Seen {
		if !t.After(cutoff) && k != next.Current {
			delete(next.Seen, k)
		}
	}
	for len(next.Seen) > maxTrackedInstances {
		oldest, oldestAt := "", now
		for k, t := range next.Seen {
			if k != next.Current && !t.After(oldestAt) {
				oldest, oldestAt = k, t
			}
		}
		if oldest == "" {
			break
		}
		delete(next.Seen, oldest)
	}

	for k := range next.Seen {
		v.Live = append(v.Live, k)
	}
	slices.Sort(v.Live)
	v.Cloned = len(next.Returns) >= CloneReturnThreshold
	return next, v
}
