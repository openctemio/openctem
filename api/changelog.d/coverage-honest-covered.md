### Fixed: coverage figures never count a failed check as covered

- The dashboard Discovery figure and the asset list filter `coverage=covered|uncovered` count an asset as covered only when every capability that applies to it succeeded in the coverage window. One working HTTP probe used to make an asset covered while its vulnerability check failed, timed out, was paused or never ran. Scope-blocked rows and the platform's DNS checks are not part of the requirement.
- The connector coverage summary (`GET /api/v1/scans/coverage`, the Tenable panel) counts a host as scanned only once its batch settled it as scanned; it counted the dispatch, so an unreachable or failed host showed as covered.
- Coverage health counts a pair paused because the host stopped answering as applicable, and as a gap once it has had no success for twice the cadence, so a host that went dark raises the gap alert instead of dropping out of every count.
