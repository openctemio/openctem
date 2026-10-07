### Added: scope policy settings page; scope refusals in words (web)

- Settings › Policies › Scope policy shows and edits the organization scope
  knobs (RFC-054 §6.3): widening approvals, one-off entries, their maximum
  length, the default probe tier and auto-join of discovered names. The values
  in effect (approvals needed now, the operator active-proof mode) are
  read-only; nothing turns scope checks off.
- "Add to scope" offers "this name only" or "this name and every name below
  it", permanent or one-off entries with a reason and a probe tier; members
  without the approve permission send a one-off request instead.
- Every scope refusal code, error code and fix action has an English and a
  Vietnamese message.

### Changed: the assets table asks the server whether each asset is in scope (web)

- The Scope column comes from `POST /api/v1/scope/check` (one call per page)
  instead of matching scope patterns in the browser, which read `*.x` the old
  way and only saw the first 100 entries. The client-side matcher is removed.

### Fixed: scope list filters were ignored (web)

- The scope entries and exclusions lists sent `target_type` / `status`; the
  API reads `types` / `statuses`, so the type filter never filtered.
