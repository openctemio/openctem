### Added: delete your own account (14-day grace) and leave an organization

- My account > Security > Delete account (`DELETE /api/v1/me/account`, step-up): every session ends
  and the account's API keys are revoked at once; signing in again within 14 days cancels; after
  that the account leaves every organization and its personal data is erased (history keeps
  "Deleted user #…"). Refused while you are the only owner of an organization, which is named.
- Settings > General > Leave this organization (`POST /api/v1/organization/leave`): the same
  offboarding an administrator runs, for yourself. The only owner cannot leave.
- Migration 002716 adds `account_deletions`.
