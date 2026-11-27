### Fixed: a notification sent as part of a grouped message is no longer logged as a dead letter

- With grouping on (the default for channels since v0.24.0), every event handed to the channel's group message was logged as an ERROR "notification channel dead-lettered after exhausting retries" (attempts 0, no error) and counted in the dead-letter metric behind the notification alert. The group message itself was sent; only the log line and the metric were wrong. A grouped delivery now counts as delivered.
- Docs: none (no setting or behaviour a user sees changes; the alert stops firing for grouped events)
