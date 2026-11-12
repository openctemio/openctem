### Added: actions and saved views on the vulnerabilities list

- Select vulnerabilities on `/vulnerabilities` (or use the actions on a vulnerability page) to create one remediation
  task for their open findings (a finding stays in at most one active task; conflicts are shown, skipped or moved),
  request one exception (accepted risk or false positive) decided by the organization's approval policy, retest the
  open findings (the 50 most urgent, each the way its source allows), or export the findings behind the rows as CSV.
  Every action covers only the findings you can see under the current filters, and is audited.
- API: `POST /api/v1/vulnerability-exposures/exception/preview`, `POST /api/v1/vulnerability-exposures/exception`
  (`findings:write`), `POST /api/v1/vulnerability-exposures/retests` (`findings:verify`),
  `GET /api/v1/vulnerability-exposures/export` (`findings:export`); each also needs `vulnerabilities:read` and
  `findings:read`.
- Saved views on the vulnerabilities list (`view=<id>` in the URL), storing the list's own filters and sort beside
  the findings filter. A view can now be shared with the whole organization by a holder of the new permission
  `findings:views:share` (owners and administrators by default); a view always runs as the person using it.
- The findings export's title falls back to the rule name, then the rule id, then the message (the title the list
  shows).
