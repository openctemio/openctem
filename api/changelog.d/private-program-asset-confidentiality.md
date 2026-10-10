### Security: private program assets are seen only by program members and owners

- A program-only asset of a private bug-bounty program, and its findings, are visible only to the program members and the organization owners. Administrators and full-data roles who are not members get 404 by id and no longer see them in asset and finding lists, exports, counts, dashboards (also with include_program_assets), the asset change feed or the EASM overview.
- Assets the organization also owns stay visible; the private program tag and flags are left out of their responses for non-members.
- Enforced once in the data-scope layer (the enforcer and the shared scope predicate). Organizations without private program assets see no change.
