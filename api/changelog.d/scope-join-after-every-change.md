### Behaviour change: approving a scope entry confirms the names it covers at once

- The scope join (names waiting for review that a permanent scope entry
  covers join the inventory) now runs after every committed change that can
  confirm a name, not only after create and activate: an entry approved
  (the usual path for a new wildcard), an entry in effect updated, an
  exclusion deleted, deactivated or shortened. It runs from the scope
  service, so review rules and later automations get it too, debounced and
  serialized per tenant. Pending entries, rejections and new exclusions
  trigger nothing.

### Added: what the scope join did, and what it would do

- Create, approve, activate and update of a scope entry answer
  `join: {confirmed_count, assets_filter: {covered_by}}`;
  `GET /api/v1/assets?covered_by=<entry id>` lists the assets confirmed
  through that entry.
- `POST /api/v1/scope/targets/preview` `{target_type, pattern}` answers
  `{would_confirm}`.
- Both counts cover only the assets the caller may see. Each run that
  confirms names writes one system audit event
  `asset.attribution_auto_confirmed`.
