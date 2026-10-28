### Added: why something is out of scope, and its findings follow

- Scope exclusions have a kind: `do_not_scan` (default; findings stay open), `not_ours` or `retired`. A permanent `not_ours` or `retired` exclusion in effect, or a "not ours" decision, closes the open findings of the assets it matches as resolved with the closure reason `out_of_scope` (never counted as fixed); taking it out of effect reopens them to their previous status. Remediation tasks, tickets and SLA follow the findings. Each pass is audited (`scope_exclusion.effects_applied`).
- A member with a limited data scope cannot create a closing rule that matches assets they cannot see (`EXCLUSION_REACHES_OUTSIDE_SCOPE`).
- The bulk exclusion preview returns `open_findings`; bulk delete (the inventory's Undo) takes 200 ids, as many as one bulk create.
- Migration `003491_scope_exclusion_kind`. Existing exclusions become `do_not_scan`: the upgrade closes nothing.
