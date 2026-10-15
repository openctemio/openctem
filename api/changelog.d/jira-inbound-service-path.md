### Behaviour change: inbound Jira changes follow the finding rules for every linked finding

- An inbound Jira status change now goes through the finding service (transition map, pentest and approval gates, tenant scope) with the Jira integration as the recorded actor and the Jira account that moved the issue in the note and the timeline, instead of writing one finding row directly. Only a verified Jira or GitHub ticket move is exempt from the person-only claim rules; other integrations are not.
- Every finding linked to the issue is moved, not one arbitrary finding. "Done" is a fix claim: the findings take the legal steps to `fix_applied`, with a proof-of-fix re-check queued for each; nothing is closed from a ticket. "In Progress" walks the legal steps too (also back from `fix_applied`).
- Findings the rules keep where they are (closed, pentest, ...) are listed with the reason in one comment on the issue, not repeated within an hour.
- Done on a campaign's epic marks the campaign's findings fixed; it no longer completes the campaign (a campaign completes when its findings are verified closed).
- Migration `002447_findings_work_item_uris_gin` adds a partial GIN index on `findings.work_item_uris` (built concurrently).
