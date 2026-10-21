### Added: the Jira assignee of a linked issue is shown on the ticket link

- Every Jira delivery (a status change or not) records the issue's assignee (Jira account id and display name), its status category and the change time on the issue's links of the integration that sent it. The ticket link API (`GET /findings/{id}/ticket-links`, `GET /remediation/tasks/{task_id}/ticket-links`) returns `external_assignee`, `external_status_category` and `external_updated_at`.
- The assignee is a label: it is never a platform assignee and grants no access. The display name is sanitized (no HTML, control or bidi characters, at most 255 characters); unlinking clears it.
- Migration `003226_ticket_links_external_assignee` adds four columns to `ticket_links` with defaults (no table rewrite).
