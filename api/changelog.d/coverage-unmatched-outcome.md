### Fixed: Coverage pairs no task carried are no longer reported as platform failures
- A pair whose name was scanned through the addresses it resolves to now takes the result of those addresses.
- A pair the sensor could not reach (TARGET_UNREACHABLE) is an unreachable pair, rechecked on the target-side schedule, and a pair the run's tasks left out is a `not_scanned` coverage gap of the organization.
- Only a pair for which no task was planned at all stays `not_dispatched`, the platform-side outcome that alerts administrators. The administrators' email says what failed.
