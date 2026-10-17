### Added: CI gate settings per repository, layered per field with locks

- A business unit or repository gate policy now sets only the fields it lists (`fields`) and inherits the rest
  from the organization, instead of replacing the whole policy. Existing policies keep their behaviour.
- The organization and business units can lock fields (`locked_fields`). No layer below can loosen a locked
  field; stricter values stay allowed.
- Loosening a business unit or repository policy needs a reason and a recent sign-in, is audited at high
  severity and is announced to administrators. A repository policy can end (`expires_at`, within 365 days).
- Gate baseline settings join the policy: `baseline_on_first_run` (default on), `baseline_grace_days` (the
  baseline findings block again after it), and `baseline_secrets_block` (default on).
- The first-run gate baseline is announced to every administrator once, like a baseline recorded by hand.
- New: `GET /api/v1/ci/gate-settings/{id}`: every setting with its effective value, inherited value,
  source and lock; `has_policy_override=true` on the pipelines list; `override_counts` per field on the gate policy
  list. Migration `ci_gate_policy_layers`.
- Deleting a business unit or repository policy that loosens the gate needs a reason too (`?reason=` on the DELETE).
  Allowing the repository's `.openctem.yml` counts as loosening, so it can be locked off.
