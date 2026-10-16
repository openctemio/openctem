### Added: accept remediation suggestions, and the opt-in auto-join rule

- Accept a suggestion as it is or edited first (title, findings to remove, other owners per partition, a
  tighter deadline): a new group creates the fix and one task per owner, a join adds the findings to the owner's
  task, a task route creates a task under the existing fix. Findings that closed or joined another task since
  are left out and reported; removed findings are not proposed for that fix again. Bulk accept up to 50
  suggestions at once.
- Auto-join, opt-in per fix and for exact fixes only (package upgrade, secret rotation): new findings with the
  fix's key join the owner's open or in-progress task without a suggestion, at most 200 a day; never into a task
  in verification; it never changes a finding's status. Turning it on needs access to every asset.
- API: `POST /api/v1/remediation/suggestions/{id}/approve`, `POST /api/v1/remediation/suggestions/approve`,
  `GET`/`PATCH /api/v1/remediation/actions/{id}`. Migration `remediation_action_auto_join`.
