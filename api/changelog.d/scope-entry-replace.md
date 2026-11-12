### Added: replace a scope entry's pattern

- The Edit scope entry dialog has a Replace pattern section: a new entry with the corrected pattern takes the old entry's place, with the checks, step-up and approvals of adding an entry. It shows the coverage added and removed and whether approval is needed before the click.
- The old entry stays in effect until the replacement is in effect, then is kept as superseded with its history; both change in one transaction. One audit event `scope_target.replaced` names both patterns and the reason.
- Scan zones that name the old range are listed; a person who may change scan zones can update them in the same flow.
- New routes `POST /api/v1/scope/targets/{id}/replace` and `/replace/preview` (`attack_surface:scope:write`). Migration `20261106174420_scope_entry_replace` (two nullable columns, a wider status constraint, a partial unique index; no rewrite).
