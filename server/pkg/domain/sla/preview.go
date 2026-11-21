package sla

// PreviewWindow is the remediation window, in days, a policy gives a finding
// of one priority class ("" = no class) and severity. Days 0 means the policy
// gives such a finding no deadline.
type PreviewWindow struct {
	PriorityClass string
	Severity      string
	Days          int
}

// DefaultPreview is what making a policy the tenant default would do to the
// open findings that default governs, measured from each finding's SLA clock
// start with the candidate's windows (the same rule that dates a new
// finding). It is a read-only estimate: making a policy the default rewrites
// no stored deadline; a deadline only moves, earlier, when the finding is next
// recomputed.
type DefaultPreview struct {
	// AlreadyDefault: the policy is the default now; every count is 0.
	AlreadyDefault bool
	// Governed counts the open findings governed by the tenant default of the
	// policy's practice (no active policy of their own asset).
	Governed int
	// Earlier counts the findings whose deadline would be earlier.
	Earlier int
	// BecomeOverdue counts the findings that are not overdue today and would
	// be past the new deadline now (including findings with no deadline yet).
	BecomeOverdue int
	// Later counts the findings whose new deadline would be later; deadlines
	// only tighten, so they keep the current one.
	Later int
}
