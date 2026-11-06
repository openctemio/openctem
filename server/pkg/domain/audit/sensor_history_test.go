package audit

import (
	"slices"
	"testing"
)

func TestSensorHistory_CanonicalMapsHistoricalIDs(t *testing.T) {
	if got := Action("agent.created").Canonical(); got != ActionSensorCreated {
		t.Errorf("Canonical(agent.created) = %q, want %q", got, ActionSensorCreated)
	}
	if got := ActionFindingCreated.Canonical(); got != ActionFindingCreated {
		t.Errorf("non-sensor action changed: %q", got)
	}
	if got := ResourceType("agent").Canonical(); got != ResourceTypeSensor {
		t.Errorf("Canonical(agent) = %q, want %q", got, ResourceTypeSensor)
	}
	if got := Action("agent.key_renewed").Category(); got != "sensor" {
		t.Errorf("historical sensor action category = %q, want sensor", got)
	}
}

func TestSensorHistory_FiltersMatchBothSpellings(t *testing.T) {
	got := WithHistoricalActions([]Action{ActionSensorConnected, ActionFindingCreated})
	for _, want := range []Action{ActionSensorConnected, "agent.connected", ActionFindingCreated} {
		if !slices.Contains(got, want) {
			t.Errorf("expanded actions %v miss %q", got, want)
		}
	}
	if len(got) != 3 {
		t.Errorf("expanded actions = %v, want exactly 3", got)
	}
	types := WithHistoricalResourceTypes([]ResourceType{ResourceTypeSensor})
	if !slices.Equal(types, []ResourceType{ResourceTypeSensor, "agent"}) {
		t.Errorf("expanded resource types = %v", types)
	}
}
