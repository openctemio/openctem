### Behaviour change: the coverage SLO gate on closing a cycle is an organization setting

- Whether a CTEM cycle below the validation coverage SLO can be closed is now each organization's policy: owners and admins switch it on the Cycles page (`GET`/`PUT /api/v1/organization/settings/cycles`, `enforce_coverage_slo`, audited as `tenant.cycle_policy_updated`). Default off: the cycle closes and the shortfall is logged, as before.
- The platform-wide `CTEM_ENFORCE_COVERAGE_SLO` environment variable is removed; startup refuses it with a hint. **Upgrade note:** if you set it to `true`, unset it and switch the policy on for the organizations that want the gate.
- A policy that cannot be read refuses the close (500) instead of guessing.
