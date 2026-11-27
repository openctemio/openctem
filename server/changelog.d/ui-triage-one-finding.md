### Fixed: triage shows one finding at a time and counts every skip (redesign branch)

- Triage: the finding and its decisions are one column; the queue opens on demand in a side panel (Queue, key `q`)
  instead of a permanent column beside the finding.
- On a phone the facts read as two columns, the decisions other than Confirm and Skip are folded under "Other
  decisions", and the bar at the bottom holds Previous, Skip and "Confirm, a real issue". The queue list is no
  longer drawn under the finding.
- A finding passed over because someone else changed it or it left your scope counts as skipped: the session line
  and "Queue done" said "0 skipped" after such skips. A run of them shows one note instead of a stack of toasts.
- No API change.
- Docs: none (the triage keys dialog lists the new `q` key).
