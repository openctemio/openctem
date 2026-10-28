### Fixed: golangci-lint no longer runs out of memory on self-hosted runners

- The "Lint (golangci-lint on new code)" step sets `GOMEMLIMIT=8GiB`, so the Go runtime collects garbage before the runner container's memory limit is reached instead of the process being killed.
