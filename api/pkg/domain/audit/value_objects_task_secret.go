package audit

// Task secrets (docs/architecture/task-secrets.md): a sensor's fetch of the
// values of a claimed job's secret refs. An event names the sensor, the
// command, the task and the refs (id, kind, class, provenance), never a
// value and never the reply key.

const (
	// ActionSecretDelivered: a sensor received sealed values for a task.
	ActionSecretDelivered Action = "secret.delivered"
	// ActionSecretRefused: an authenticated sensor's fetch was refused
	// (the reason is in the metadata; the sensor was told
	// command-not-found).
	ActionSecretRefused Action = "secret.refused"
)

var _ = registerActions("secret", map[Action]Severity{
	ActionSecretDelivered: SeverityLow,
	ActionSecretRefused:   SeverityLow,
})
