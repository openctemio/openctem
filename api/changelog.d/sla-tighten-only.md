### Behaviour change: SLA deadlines only tighten when a priority or policy changes

- When an open finding's priority rises, its deadline becomes min(old deadline, now + the new class's SLA). It used to be recomputed from the detection date, which set a deadline already in the past (an instant breach) for a late escalation.
- A priority drop no longer extends the deadline, and an overdue finding stays overdue. Before, the drop moved the deadline later and could turn `overdue` back into `on_track`.
- An SLA policy edit now applies to open findings from the change time, tighten-only: a shorter policy pulls deadlines in, a longer one only affects new findings. Closed findings keep their deadline.
- Every tightening writes a `sla_deadline_tightened` entry on the finding's timeline, with both deadlines, both classes and the reason.
- The database enforces the rule for every writer: an update that would move an open finding's deadline later, or clear it, keeps the stored deadline, so a stale full-row write or a recompute that read the row before a tightening cannot extend it. Only the regression restart and the end of a risk acceptance start a new, later clock.
- Upgrade note: the `finding_activities` activity-type constraint is re-added `NOT VALID` and validated by a separate migration, so the large table is not scanned under an exclusive lock.
