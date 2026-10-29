package coverage

// Coverage alerts on change (docs/rfcs/RFC-093-asset-coverage.md): an
// alert is keyed by (capability, kind, reason), so a tenant has at most one
// open alert per key. It is sent when the condition appears, and again only
// when it gets clearly worse (the count at least doubles and grows by
// AlertMinRise since it was last sent, at most once per AlertRenotifyAfter);
// an improvement updates the open alert silently, and the alert is resolved
// (cleared) when the condition goes away. A condition that comes back within
// AlertQuietAfterClear of clearing comes back silently. Several changes in
// one pass go out as one digest, at most one digest per tenant per day.

import (
	"strings"
	"time"
)

// AlertReadiness is the alert kind of a capability paused for a readiness
// reason (the reason is part of the key).
const AlertReadiness = "readiness"

// Alert timing.
const (
	// AlertQuietAfterClear: a condition that comes back within this time
	// of clearing is not sent again. Several cadences of a daily
	// capability, so a streak or gap that flaps across days stays one
	// alert.
	AlertQuietAfterClear = 72 * time.Hour
	// AlertRenotifyAfter: an open alert that gets worse is sent again at
	// most once per this time.
	AlertRenotifyAfter = 24 * time.Hour
	// DigestEvery: at most one digest of several changes per tenant per
	// this time.
	DigestEvery = 24 * time.Hour
)

// AlertMinRise is the smallest growth of an open alert's count, over the
// count last sent, that sends it again: on a handful of assets a count that
// moves 2 -> 6 -> 2 as single runs fail and pass is noise, not news.
const AlertMinRise = 5

// DigestCapability and DigestKind key the tenant's digest row.
const (
	DigestCapability = "*"
	DigestKind       = "digest"
)

// AlertCondition is one alert condition that holds now.
type AlertCondition struct {
	Capability string
	Kind       string
	Reason     string
	Count      int
}

// Key identifies the condition's alert.
func (c AlertCondition) Key() AlertKey { return AlertKey{c.Capability, c.Kind, c.Reason} }

// AlertKey is (capability, kind, reason).
type AlertKey struct {
	Capability, Kind, Reason string
}

// AlertState is the stored state of one alert key of a tenant.
type AlertState struct {
	AlertKey
	Active    bool
	SentCount int
	LastCount int
	SentAt    *time.Time
	ClearedAt *time.Time
}

// Conditions returns the alert conditions of a tenant's health. A platform
// check (dns.*) that keeps failing on single assets is an asset-level fact
// shown on the asset, not an administrator alert.
func Conditions(health []CapabilityHealth) []AlertCondition {
	var out []AlertCondition
	for _, h := range health {
		for _, kind := range h.Alerts() {
			c := AlertCondition{Capability: h.Capability, Kind: kind}
			switch kind {
			case AlertGap:
				c.Count = h.Gaps
			case AlertOutputDrop:
				c.Count = h.NoOutput
			case AlertFailing:
				if strings.HasPrefix(h.Capability, "dns.") {
					continue
				}
				c.Count = h.Failing
			}
			out = append(out, c)
		}
		if h.Paused > 0 && IsReadinessReason(h.PausedReason) {
			out = append(out, AlertCondition{Capability: h.Capability, Kind: AlertReadiness, Reason: h.PausedReason, Count: h.Paused})
		}
	}
	return out
}

// PlanAlerts decides which conditions to send now and the states to store.
// states are the tenant's stored states (the digest row included).
// Conditions to send come with the states that record the send; when they
// are several and a digest went out within DigestEvery, nothing is sent and
// those sends stay pending (their states are not advanced).
func PlanAlerts(states []AlertState, conds []AlertCondition, now time.Time) (send []AlertCondition, store []AlertState) {
	byKey := make(map[AlertKey]AlertState, len(states))
	var digest *AlertState
	for i := range states {
		if states[i].Capability == DigestCapability && states[i].Kind == DigestKind {
			digest = &states[i]
			continue
		}
		byKey[states[i].AlertKey] = states[i]
	}
	var sends []AlertState
	seen := make(map[AlertKey]bool, len(conds))
	for _, c := range conds {
		k := c.Key()
		seen[k] = true
		st, ok := byKey[k]
		sent := AlertState{AlertKey: k, Active: true, SentCount: c.Count, LastCount: c.Count, SentAt: &now}
		switch {
		case !ok:
			send, sends = append(send, c), append(sends, sent)
		case !st.Active && st.ClearedAt != nil && now.Sub(*st.ClearedAt) < AlertQuietAfterClear:
			// Back within a day of clearing: silent.
			st.Active, st.LastCount, st.ClearedAt = true, c.Count, nil
			store = append(store, st)
		case !st.Active:
			send, sends = append(send, c), append(sends, sent)
		case worse(st, c.Count, now):
			send, sends = append(send, c), append(sends, sent)
		case c.Count != st.LastCount:
			// Better, or not worse enough: the open alert is updated in
			// place, nobody is notified.
			st.LastCount = c.Count
			store = append(store, st)
		}
	}
	for k, st := range byKey {
		if st.Active && !seen[k] {
			st.Active, st.ClearedAt = false, &now
			store = append(store, st)
		}
	}
	if len(send) > 1 {
		if digest != nil && digest.SentAt != nil && now.Sub(*digest.SentAt) < DigestEvery {
			return nil, store
		}
		store = append(store, AlertState{AlertKey: AlertKey{DigestCapability, DigestKind, ""}, Active: true,
			SentCount: len(send), LastCount: len(send), SentAt: &now})
	}
	return send, append(store, sends...)
}

// worse reports whether an open alert's new count is news: at least double
// the count last sent and AlertMinRise more, and the last send is older than
// AlertRenotifyAfter (until then it stays pending and is decided again on
// the next pass). A count going down is never sent.
func worse(st AlertState, count int, now time.Time) bool {
	if count < 2*st.SentCount || count-st.SentCount < AlertMinRise {
		return false
	}
	return st.SentAt == nil || now.Sub(*st.SentAt) >= AlertRenotifyAfter
}

// AlertAction is what an administrator can do about an alert, and where.
type AlertAction struct {
	Text string
	URL  string
}

// ActionFor returns the action of an alert condition. Server-generated
// English: it reaches integrations verbatim.
func ActionFor(c AlertCondition) AlertAction {
	if c.Kind != AlertReadiness {
		return AlertAction{Text: "Open the assets to see which ones and why.", URL: "/assets"}
	}
	switch c.Reason {
	case ReadyNoScope:
		return AlertAction{"Add your domains and ranges to scope.", "/scope"}
	case ReadyToolMissing:
		return AlertAction{"Add the tool to a sensor (Settings > Scanning > Tools shows how).", "/settings/scanning/tools"}
	case ReadyToolNotAllowed:
		return AlertAction{"Allow the tool in the sensor's grant or local policy.", "/sensors"}
	case ReadySensorOffline:
		return AlertAction{"Start the sensor, or wait until it reconnects.", "/sensors"}
	case ReadySensorOutdated:
		return AlertAction{"Update the sensor to the tool's minimum version.", "/sensors"}
	case ReadyNoEligibleSensor:
		return AlertAction{"Install a sensor, or assign one to the scan zone.", "/sensors"}
	case ReadyCredentialsMissing:
		return AlertAction{"Add the API key the tool needs.", "/settings/scanning/tools"}
	case ReadyQuotaExhausted:
		return AlertAction{"It resumes at 00:00 UTC; add your own sensor to scan more.", "/sensors"}
	case ReadyNotClaimed:
		return AlertAction{"Open a waiting run's \"Why waiting?\" or check the sensors' grants and policies; coverage tries again on its own.", "/sensors"}
	default: // ReadyPolicyDisabled
		return AlertAction{"Turn the tool on in Settings > Scanning > Tools, or check scan approval and windows.", "/settings/scanning/tools"}
	}
}

// readinessText says why a capability cannot run, for alert text.
var readinessText = map[string]string{
	ReadyPolicyDisabled:     "an organization policy holds it",
	ReadyNoScope:            "the organization has no scope entry",
	ReadyToolMissing:        "no sensor has the tool it needs",
	ReadyToolNotAllowed:     "the sensors' policy does not allow its tool",
	ReadySensorOffline:      "the sensors with its tool are offline",
	ReadySensorOutdated:     "the sensors with its tool are too old",
	ReadyNoEligibleSensor:   "no sensor can take the work",
	ReadyCredentialsMissing: "an API key it needs is not configured",
	ReadyQuotaExhausted:     "today's shared scanning quota is used up",
	ReadyNotClaimed:         "no sensor took its last runs",
}

// ReadinessText returns the English phrase of a readiness reason.
func ReadinessText(reason string) string {
	if t, ok := readinessText[reason]; ok {
		return t
	}
	return reason
}
