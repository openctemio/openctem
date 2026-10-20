### Security: reopening an approved false positive or accepted risk needs findings:approve

- Moving a finding out of an approved false positive or an accepted risk (status route and bulk status) now needs `findings:approve`, the permission that made the decision, in addition to `findings:status`. The allowed-moves list reports the missing permission.
- Workflow actions and ticket webhooks can no longer move a finding out of a decided status (false positive, accepted risk, duplicate; for workflows also resolved).
- **Upgrade note:** the built-in Owner and Admin roles hold `findings:approve`. A custom role that reopens decided findings must be granted it; reopening a resolved finding by a person is unchanged.
