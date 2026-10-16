### Behaviour change: a secret found by CI on a non-fork branch is an organization finding with a rotation task

- A secret a CI run finds on any non-fork branch (pull requests included) is now an organization finding at once instead of staying hidden as seen only on a branch, and a remediation task "Rotate <secret type>" is opened for it. The task is per secret identity: the same credential in other repositories or branches joins the open task, never a second one. Fork runs raise nothing.
- Only secrets that are not validated false and not matched by a generic or heuristic rule page: they block the gate and open a task. A hard-coded password hit or a dead secret follows the policy's severity and modes like any finding, so it no longer blocks every pipeline.
- Added: remediation action origin `system` (migration `remediation_action_origin_system`).
- Security: the validity a CI upload reports for a secret is no longer stored or trusted by the gate, and generic rules are matched against an explicit list of scanner rule ids. At most one active task exists per remediation action (migration `remediation_task_one_active_per_action`).
