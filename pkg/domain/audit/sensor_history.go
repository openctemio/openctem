package audit

import "strings"

// Audit rows written before the agent → sensor rename (RFC-023 §9.5) carry
// action "agent.*" and resource_type "agent". They are never rewritten: the
// audit log is hash-chained, and changing a historical row would break chain
// verification by design. New events are "sensor.*" / "sensor".
//
// Reads treat both spellings as one event family: a filter for a sensor
// action or resource type also matches the historical spelling, and
// Canonical maps a historical value onto its current name.
const (
	historicalSensorActionPrefix = "agent."
	sensorActionPrefix           = "sensor."
	historicalResourceTypeSensor = ResourceType("agent")
)

// Canonical returns the current name of an action, mapping a historical
// "agent.*" action onto "sensor.*". Other actions are returned unchanged.
func (a Action) Canonical() Action {
	if rest, ok := strings.CutPrefix(string(a), historicalSensorActionPrefix); ok {
		return Action(sensorActionPrefix + rest)
	}
	return a
}

// Canonical returns the current name of a resource type ("agent" → "sensor").
func (r ResourceType) Canonical() ResourceType {
	if r == historicalResourceTypeSensor {
		return ResourceTypeSensor
	}
	return r
}

// WithHistoricalActions returns the actions plus, for each sensor action,
// the spelling historical rows were written with.
func WithHistoricalActions(actions []Action) []Action {
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		out = append(out, a)
		if rest, ok := strings.CutPrefix(string(a), sensorActionPrefix); ok {
			out = append(out, Action(historicalSensorActionPrefix+rest))
		}
	}
	return out
}

// WithHistoricalResourceTypes returns the resource types plus the historical
// spelling of the sensor resource type when it is among them.
func WithHistoricalResourceTypes(types []ResourceType) []ResourceType {
	out := make([]ResourceType, 0, len(types))
	for _, t := range types {
		out = append(out, t)
		if t == ResourceTypeSensor {
			out = append(out, historicalResourceTypeSensor)
		}
	}
	return out
}
