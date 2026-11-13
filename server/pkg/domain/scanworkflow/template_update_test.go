package scanworkflow

import (
	"slices"
	"testing"
)

func spec(steps ...SpecStep) Spec { return Spec{Steps: steps} }

func step(key string, order int, deps ...string) SpecStep {
	return SpecStep{ID: "id-" + key, StepKey: key, Name: key, StepOrder: order, DependsOn: deps, Capabilities: []string{"cap." + key}}
}

// The Network template before and after it gained Host discovery.
var (
	networkBefore = spec(step("ports", 1), step("http", 2, "ports"), step("vulns", 3, "http"))
	networkAfter  = spec(step("hosts", 1), step("ports", 2, "hosts"), step("http", 3, "ports"), step("vulns", 4, "http"))
)

func TestTemplateChanges_HostDiscovery(t *testing.T) {
	copySpec := networkBefore
	got := TemplateChanges(networkBefore, networkAfter, copySpec)
	if len(got) != 2 {
		t.Fatalf("changes = %+v, want add hosts and rewire ports", got)
	}
	if got[0].Kind != ChangeAddStep || got[0].StepKey != "hosts" || len(got[0].DependsOn) != 0 {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Kind != ChangeDependsOn || got[1].StepKey != "ports" || !slices.Equal(got[1].DependsOn, []string{"hosts"}) {
		t.Errorf("second = %+v", got[1])
	}

	applied := ApplyTemplateChanges(copySpec, networkAfter, got)
	keys := map[string]SpecStep{}
	for _, st := range applied {
		keys[st.StepKey] = st
	}
	if h, ok := keys["hosts"]; !ok || h.ID != "" || h.StepOrder != 4 || !slices.Equal(h.Capabilities, []string{"cap.hosts"}) {
		t.Errorf("added step = %+v", keys["hosts"])
	}
	if !slices.Equal(keys["ports"].DependsOn, []string{"hosts"}) || keys["ports"].ID != "id-ports" {
		t.Errorf("ports = %+v (keeps its id, depends on hosts)", keys["ports"])
	}
	// Applied: nothing more to offer.
	if again := TemplateChanges(networkAfter, networkAfter, spec(applied...)); len(again) != 0 {
		t.Errorf("after apply: %+v", again)
	}
}

func TestTemplateChanges_TheCopyIsTheTenants(t *testing.T) {
	cases := map[string]struct {
		base, copySpec Spec
		want           []string
	}{
		"a copy made after the change has nothing to take":    {networkAfter, networkAfter, nil},
		"no recorded base: the copy's own steps are the base": {networkBefore, networkBefore, []string{"add_step:hosts", "depends_on:ports"}},
		"the tenant rewired ports: only the step is offered": {networkBefore,
			spec(step("ports", 1, "http"), step("http", 2), step("vulns", 3, "http")), []string{"add_step:hosts"}},
		"the tenant removed ports: it is not brought back, nothing depends on it": {networkBefore,
			spec(step("http", 1), step("vulns", 2, "http")), []string{"add_step:hosts"}},
		"the tenant added hosts already: not added twice": {networkBefore,
			spec(step("hosts", 1), step("ports", 2), step("http", 3, "ports"), step("vulns", 4, "http")), []string{"depends_on:ports"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, c := range TemplateChanges(tc.base, networkAfter, tc.copySpec) {
				got = append(got, c.Kind+":"+c.StepKey)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("changes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTemplateChanges_RemovedTemplateStepsAreNotOffered(t *testing.T) {
	after := spec(step("ports", 1), step("http", 2, "ports"))
	if got := TemplateChanges(networkBefore, after, networkBefore); len(got) != 0 {
		t.Fatalf("changes = %+v, want none (a removed step is the copy's to keep)", got)
	}
}
