### Fixed: validation, remediation and access-control confirmations name what they delete and are translated (part 5)

- Confirmations for pentest campaigns, findings, reports and evidence, campaign members,
  controls, suppression rules, remediation tasks, finding approval requests, evidence notes,
  threat actors, indicators, comments, teams (delete, remove member, remove asset, remove role),
  assignment rules, scope rules, capabilities and CI pipeline retirement now name the object,
  state the consequence and are translated (English and Vietnamese).
- Deleting a pentest campaign, which deletes its findings, asks the user to type its name; bulk
  deletes of ten or more pentest reports ask for the count.
- The team, assignment-rule, scope-rule and evidence-note deletes use the shared confirmation
  (Cancel focused, no double submit) instead of their own dialogs.
