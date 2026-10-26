### Added: roles and order for a finding's evidence, and an evidence version

- Evidence items on a finding now have a role (baseline, proof, verification or supporting) and a position. A person with write access to findings sets the role and the order from the Evidence tab; the change is audited and shown on the finding's timeline. New items are supporting and keep the newest-first order until someone orders them.
- `findings.evidence_version` counts every change to a finding's evidence (added, removed, re-roled, reordered). The evidence list returns it with a proof count. Migration 003440 adds the columns and the triggers that keep the version; it takes no long lock, and the version bump leaves `row_version` alone.
- New routes: `PATCH /api/v1/findings/{id}/evidence-items/{item_id}` and `PUT /api/v1/findings/{id}/evidence-items/order`. On a pentest finding they follow the campaign's evidence rules.
