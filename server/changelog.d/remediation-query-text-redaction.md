### Security: a task's query text is masked for readers outside its author's scope

- The text of the query a remediation task was created from could name assets, addresses or people outside the data scope of a member who sees the task through one finding. `GET /api/v1/remediation/tasks/{task_id}/query`, the re-run preview, the auto-include state answer, the task timeline and the re-run audit entry now give the full text only to the query's owner, administrators and full-data roles; other readers get the query with its names, addresses, ids and free text masked as `"***"` (fields, operators, numbers, relative dates and enum values stay), and `query_redacted: true`.
- Docs: server/docs/rfcs/RFC-098-remediation-tasks.md
