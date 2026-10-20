### Fixed: dashboard facts no longer try to build the platform's system row

- The dashboard facts maintainer listed the all-zero system tenant (shared templates) as an organization needing an initial build and logged "tenant id is required" every few minutes. It now skips that row.
