### Behaviour change: SLA deadlines only tighten when a priority or policy changes

- When an open finding's priority rises, its deadline becomes min(old deadline, now + the new class's SLA). It used to be recomputed from the detection date, which set a deadline already in the past (an instant breach) for a late escalation.
- A priority drop no longer extends the deadline, and an overdue finding stays overdue. Before, the drop moved the deadline later and could turn `overdue` back into `on_track`.
- An SLA policy edit now applies to open findings from the change time, tighten-only: a shorter policy pulls deadlines in, a longer one only affects new findings. Closed findings keep their deadline.
- Every tightening writes a `sla_deadline_tightened` entry on the finding's timeline, with both deadlines, both classes and the reason (migration 002216).
