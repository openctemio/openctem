package postgres

// Every statement that returns a command to pending counts the return in
// requeue_count and pushes the next offer out by command_requeue_backoff_secs
// (scheduled_at, which the claim predicates already honor), so a command that
// cycles between a sensor and the queue slows down and is failed once
// command.MaxRequeues is reached (FailExhaustedCommandsReturning). A scan
// window deferral sets its own scheduled_at and only counts.

// requeueDueSQL is the scheduled_at a re-queue sets: never earlier than the
// command's own schedule, delayed by the back-off of its next count. prefix is
// the table alias with its dot ("" or "c.").
func requeueDueSQL(prefix string) string {
	return `GREATEST(COALESCE(` + prefix + `scheduled_at, NOW()), NOW() + make_interval(secs => command_requeue_backoff_secs(` + prefix + `requeue_count + 1)))`
}

// requeueCountSQL only counts the return (a refusal re-route: another sensor
// may take the command at once).
func requeueCountSQL(prefix string) string {
	return `requeue_count = ` + prefix + `requeue_count + 1`
}

// requeueSQL is the SET items of a re-queue: the counter and the delay.
func requeueSQL(prefix string) string {
	return `requeue_count = ` + prefix + `requeue_count + 1, scheduled_at = ` + requeueDueSQL(prefix)
}
