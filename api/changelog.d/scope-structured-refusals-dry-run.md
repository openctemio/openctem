### Changed: scope refusals say why and how to fix it; `POST /scope/check` is a dry run of the whole gate

- A scan request refused for its targets (`TARGET_OUT_OF_SCOPE`) now lists
  every refused target in `details.refused[]` with a code (`no_entry`,
  `rejected`, `needs_review`, `deny_list`, `proof_required`, …), a message and
  the fixes that would let it through (RFC-054 §6.5). Dispatch-gate refusals
  carry the code too.
- `POST /api/v1/scope/check` now takes `{"targets": [...], "sensor_preference",
  "tier"}` and answers, per target, what a scan by the caller would do:
  allowed with what authorizes it (scope target, seed, verified domain; proof
  level; zone), or refused with the code, the caller's own rule (a pending,
  expired or deactivated entry; an exclusion) and the fixes the caller may
  take. It dispatches, logs and audits nothing.
- **Removed:** the old `POST /scope/check` body `{"asset_type", "value"}` and
  its `in_scope`/`excluded` answer.
