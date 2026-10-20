### Added: the task owner picker says who cannot see the task's findings

- New `GET /api/v1/remediation/tasks/{task_id}/owner-candidates` (and `GET /api/v1/remediation/tasks/owner-candidates?finding_ids=` for a task not created yet) lists people and teams with how many open findings and assets each cannot see. Counts only, never finding titles.
- The Split dialog shows "Needs access to N findings on M assets" per candidate. Without `findings:assign` those candidates cannot be picked and "Request access" leaves an internal comment on a finding (it grants nothing); with it a consent line must be ticked.
- Naming an owner who cannot see some of the open findings (create, owner change, adding primary findings, split) now answers `422` unless the caller holds `findings:assign` and sends `confirm_owner_access: true`. An accepted case is audited as `remediation_task.owner_access_extended` with the counts.
- **Behaviour change:** API clients that set a task owner who lacks access to its findings must send `confirm_owner_access` and need `findings:assign`.
