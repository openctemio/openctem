### Added: remediation suggestions

- The platform proposes remediation groups from the remediation keys (one package upgrade, one leaked secret,
  one specific solution): one suggestion per fix, its findings split by the asset's primary owner, ranked by
  risk reduced. Nothing is created until a person accepts; a key that already has an action yields "join this
  task" or "new task for this owner" proposals instead.
- Lifecycle: dismiss with a reason (held until the suggestion changes materially), snooze (up to 180 days),
  reopen; suggestions expire when their findings close. At most 50 new suggestions are shown per organization
  per day; reviewers get one daily digest notification (event `remediation_suggestions_digest`).
- API `/api/v1/remediation/suggestions` (list, stats, run, get, members, snooze, reject, reopen) in the
  remediation module. A restricted member sees only their findings of a suggestion and may not decide on one
  with others. Design: RFC-098 §5. Migration `remediation_suggestions` (three new tables).
