### Added: path exclusions and their testing mode on the Scope page (web)

- Scope › "Put out of scope" can exclude only a path (RFC-056 §5): a host
  pattern, a path prefix and the methods it blocks, with a "block only what
  changes state" suggestion so read-only checks still run there.
- Out of scope shows a path exclusion as host + path, the methods it blocks
  and its testing mode (Blocked, Read-only, Allowed with the date it is
  blocked again).
- "Testing mode…" (exclusion approvers only) changes it in two steps: choose
  the mode and an end (required for Allowed, at most 90 days), then review
  what changes. The API asks for step-up, audits the change and notifies
  every administrator; it never widens scope beyond the organization's
  assets, and there is no switch that lifts every exclusion at once.
