### Added: daily digest of finding requests for each approver

- Once a day, every approver who has finding requests to decide gets one
  in-app notice (type `finding_approval_digest`) and one email: how many wait
  for them, how many expire within two days, and up to five titles. Only
  requests they may decide count (never their own, the finding in their data
  scope); titles are those of findings they can see; no justification or
  evidence is sent. Service accounts get none.
- Muting "Approvals digest" in the notification settings opts out (in-app and
  email; it can be muted even with in-app notifications off). The settings
  page now shows every notification type in English and Vietnamese.
- A new hourly `approval-digest` controller sends it, at most once per
  approver and organization per 23 hours (`finding_approval_digest_sent`,
  migration `002780`; a new per-tenant table, deleted with the member's
  account).
