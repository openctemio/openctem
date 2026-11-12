### Security: every automatic close path follows the organization's closing mode

- A coverage run held by the blinding guard no longer proposes closes when the organization's closing mode is `off`; in `review` and `auto` it still proposes, and closes nothing.
- A retest that confirms a fix with the retest setting `auto_resolve` on now passes the closing mode (method `retest_verified`): `auto` resolves, `review` records a Ready to close proposal instead, `off` keeps the finding open. Confirming such a proposal records verification `retest`.
- Every finding status a retest moves (a resolve, a regression reopen, a rejected fix) writes a `finding.status_changed` audit row in the same transaction, high when it closes a critical, P0 or KEV finding.

### Behaviour change: retest auto-resolve in organizations without a closing mode

- An organization created before the closing mode existed reads as `review`: its passing retests with `auto_resolve` on now become Ready to close proposals instead of closing on their own. Set the closing mode to `auto` (Settings > Finding lifecycle) to keep the old behaviour.
