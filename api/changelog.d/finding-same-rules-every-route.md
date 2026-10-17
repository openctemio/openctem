### Security: the same claim and close rules on every route

- `PATCH /api/v1/findings/{id}/status`, the bulk status change and remediation
  group and campaign resolves now apply the rules of the dedicated actions:
  marking a fix applied needs `findings:fix_apply`, a note, and the finding to
  be the person's (assignee, assigned group or asset owner); a resolve that is
  not backed by a complete verification checklist is recorded as attested and
  needs a note. An organization API key (no user) gets the same rules and
  cannot claim a fix at all. Before, `PATCH` with `findings:status` alone could claim a fix
  on anyone's finding without a note, and close without a checklist or note.
- The web asks for the note in the drawer's status control and in the bulk,
  group and campaign resolve dialogs.
