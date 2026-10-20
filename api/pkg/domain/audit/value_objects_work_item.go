package audit

// Watchers of findings and remediation tasks (RFC-120). Only adding or
// removing ANOTHER person is audited: a person's own bell and the rows that
// participation adds automatically are personal preferences, high in volume
// and without security weight. Target user ids are recorded, never emails.
const (
	// ActionWorkItemWatcherAdded: a person added someone as a watcher.
	ActionWorkItemWatcherAdded Action = "work_item.watcher_added"
	// ActionWorkItemWatcherRemoved: a person removed someone else as a watcher.
	ActionWorkItemWatcherRemoved Action = "work_item.watcher_removed"
)

var _ = registerActions("work_item", map[Action]Severity{
	ActionWorkItemWatcherAdded:   SeverityLow,
	ActionWorkItemWatcherRemoved: SeverityLow,
})
