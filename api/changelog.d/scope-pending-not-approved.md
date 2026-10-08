### Fixed: a pending scope entry has no approval time

- A scope entry waiting for approval no longer reports `approved_at`; it is set when the entry is approved (or at creation when it needs no approval).
- Migration `001362_scope_pending_not_approved` clears the approval time stored on pending and rejected entries.
