package automation

// Risk classes (RFC-125 D6). The class of an automation is the highest class
// of its steps; the go-live gate asks more of a riskier automation.
//
//   - low: internal and reversible (tags);
//   - elevated: changes the workflow state of a finding or leaves the
//     platform (status, assignment, tickets, notifications, AI triage);
//   - high: starts work or creates decisions at scale (scans, false-positive
//     and risk-acceptance requests), and any automation that lets events
//     caused by other automations start it (chaining).

// RiskClass is the impact class of a step or an automation.
type RiskClass string

// Risk classes, lowest first.
const (
	RiskLow      RiskClass = "low"
	RiskElevated RiskClass = "elevated"
	RiskHigh     RiskClass = "high"
)

// IsValid reports whether r is a known class.
func (r RiskClass) IsValid() bool { return r == RiskLow || r == RiskElevated || r == RiskHigh }

func (r RiskClass) rank() int {
	switch r {
	case RiskHigh:
		return 2
	case RiskElevated:
		return 1
	}
	return 0
}

// Max returns the higher of r and o.
func (r RiskClass) Max(o RiskClass) RiskClass {
	if o.rank() > r.rank() {
		return o
	}
	if r == "" {
		return RiskLow
	}
	return r
}

// ActionRisk is the class of an action type. An unknown type is high: it is
// refused anyway, and nothing unknown is treated as harmless.
func ActionRisk(t ActionType) RiskClass {
	switch t {
	case ActionTypeAddTags, ActionTypeRemoveTags:
		return RiskLow
	case ActionTypeAssignUser, ActionTypeUpdateStatus, ActionTypeCreateTicket,
		ActionTypeUpdateTicket, ActionTypeTriggerAITriage:
		return RiskElevated
	}
	// trigger_scan, request_false_positive, request_risk_acceptance and
	// anything unknown.
	return RiskHigh
}

// NotificationRisk is the class of a notification: it leaves the platform.
func NotificationRisk(NotificationType) RiskClass { return RiskElevated }

// ConfigRisk is the class of one node config.
func ConfigRisk(c NodeConfig) RiskClass {
	r := RiskLow
	if c.ActionType != "" {
		r = r.Max(ActionRisk(c.ActionType))
	}
	if c.NotificationType != "" {
		r = r.Max(NotificationRisk(c.NotificationType))
	}
	if c.TriggerType != "" {
		if allow, _ := c.TriggerConfig["allow_automation_triggers"].(bool); allow {
			r = r.Max(RiskHigh)
		}
	}
	return r
}

// Risk is the class of the definition: the highest class of its nodes; a
// change cap above the default makes it high.
func (d Definition) Risk() RiskClass {
	r := RiskLow
	if d.MaxChangesPerRun > DefaultMaxChangesPerRun {
		r = RiskHigh
	}
	for _, n := range d.Nodes {
		r = r.Max(ConfigRisk(n.Config))
	}
	return r
}
