### Added: an explicit way to cancel a waiting approval-settings change

- `PUT /api/v1/organization/settings/finding-approvals/` accepts `cancel_pending: true`: it drops the waiting lowering of the false-positive level, the second-look share and a relaxing policy, and keeps the values in force. Cancel no longer works by saving the current values again.
