### Security: a scan command created through POST /commands is refused above its scope tier

- `POST /api/v1/commands` with type `scan` now applies the tier ceiling of a scan trigger: a target whose scope entries allow less than the named scanner probes at (its tier; T1 for an unknown scanner) refuses the command (`TARGET_OUT_OF_SCOPE`, 400, with `tier_exceeds` and the `raise_tier` fix), and a failed tier lookup refuses it.
- The command records that tier, so the claim-time scope re-check also catches a tier lowered while the command waits in the queue (`SCOPE_CHANGED`).
