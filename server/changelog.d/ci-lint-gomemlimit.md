### Fixed: golangci-lint no longer runs out of memory on self-hosted runners

- The "Lint (golangci-lint on new code)" step sets `GOMAXPROCS=4` and `GOMEMLIMIT=8GiB`. The pinned golangci-lint ignores the container's CPU limit and started one type-check worker per host CPU; it now uses the runner's 4 CPUs, and the Go runtime collects garbage before the container's memory limit is reached instead of the process being killed.
