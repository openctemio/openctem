### Added: how a finding can be verified, from the server

- `GET /api/v1/findings/{id}/verification` (`findings:read`, data scope applies) returns the finding's risk tier, what a person's resolve needs at that tier, each verification method (retest, covered scan, safe-check, rotation proof, evidence review) with whether it is available and a reason code when not, and the proof recorded so far (latest retest, checklist state and who completed it, whether it is fresh).
- The retest service reports why a retest would be refused (for example `secret_needs_rotation`, `asset_not_network_addressable`, `no_sensor`) instead of only yes or no.
