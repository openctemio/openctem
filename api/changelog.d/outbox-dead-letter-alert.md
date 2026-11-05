### Fixed: the OutboxDeadLetters alert fires when a notification gives up

- The alert read the number of outbox rows in status `dead`, but the outbox archives and removes a finished entry at once and the per-channel delivery never sets that status, so the alert could not fire.
- New counter `openctem_notification_dead_letters_total` (label `where`: `channel` when one integration's retries ran out, `entry` when the event's integrations or routing could not be read within the retries). `OutboxDeadLetters` now fires on `sum(increase(...[1h])) > 0`. An entry that gives up at entry level now also logs an ERROR.
