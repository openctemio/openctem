### Added: approve a sensor as trusted, with its networks and scope, in one step

- The approve form can make a new sensor **Trusted for active scanning**. This is offered only for a sensor that started with the code the console made, for the internal scanner, external attack surface and scanner connector profiles, and to someone with `sensors:grant:widen`. The approval's step-up counts as the re-authentication, and the change is audited and announced like a promotion. Codes the sensor printed itself, enrollment tokens, re-pairs, authenticated scanners and collectors still start New.
- The approve form takes the **networks the sensor scans** (private ranges only, `sensors:zones:write`). The sensor joins the scan zone with exactly those ranges, or a new zone is created for it, in the same transaction.
- **Also add to scope** adds the networks to scope after the approval, as a separate entry through the usual scope approvals.
- `POST /api/v1/sensor-pairings/{id}/approve` takes `trusted` and `ranges`; pairing views carry `trust_eligible`.
