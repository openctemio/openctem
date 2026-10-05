package audit

// A registry for actions declared outside value_objects.go. Each feature
// file registers its own set at package init (value_objects_easm.go, ...),
// so adding an action is a one-file change: the
// action is accepted by IsValid, gets its category and its default severity
// from the same declaration, and two features adding actions in parallel do
// not edit the same switch.

type registeredAction struct {
	category string
	severity Severity
}

var registeredActions = map[Action]registeredAction{}

// registerActions records actions of one category with their default
// severity. It panics on a duplicate, so two features cannot claim the same
// action string with different meanings.
func registerActions(category string, actions map[Action]Severity) struct{} {
	for a, sev := range actions {
		if _, dup := registeredActions[a]; dup {
			panic("audit: action registered twice: " + string(a))
		}
		registeredActions[a] = registeredAction{category: category, severity: sev}
	}
	return struct{}{}
}

func isRegisteredAction(a Action) bool {
	_, ok := registeredActions[a]
	return ok
}

func registeredCategory(a Action) (string, bool) {
	r, ok := registeredActions[a]
	return r.category, ok
}

func registeredSeverity(a Action) (Severity, bool) {
	r, ok := registeredActions[a]
	return r.severity, ok
}
