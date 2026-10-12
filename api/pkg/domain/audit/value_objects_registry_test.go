package audit

import "testing"

// Every registered action is accepted, has a category and a valid severity,
// and does not reuse a string declared in value_objects.go.
func TestRegisteredActions(t *testing.T) {
	declared := map[string]bool{}
	for _, v := range declaredConsts(t, "Action") {
		declared[v] = true
	}
	if len(registeredActions) == 0 {
		t.Fatal("no registered actions")
	}
	for a, r := range registeredActions {
		if declared[string(a)] {
			t.Errorf("%s is declared in value_objects.go and registered again", a)
		}
		if !a.IsValid() || a.Category() != r.category || r.category == "" {
			t.Errorf("%s: valid=%v category=%q", a, a.IsValid(), a.Category())
		}
		if !r.severity.IsValid() || SeverityForAction(a) != r.severity {
			t.Errorf("%s: severity %q", a, r.severity)
		}
	}
}

func TestRegisterActionsRefusesDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a duplicate registration must panic")
		}
	}()
	registerActions("scan", map[Action]Severity{ActionScanTargetRefused: SeverityLow})
}
