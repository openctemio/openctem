### Added: where and when a finding was seen, in the finding drawer

- `GET /api/v1/findings/{id}` returns `provenance`: the branches the finding was seen on with their first and last commit and status, and, for a caller holding `scans:ci:read`, the CI pipelines that reported it (the newest five and the first one, with the pipeline link and merge request). Run actors and tokens are never included.
- The finding drawer has a Provenance section: first seen (branch, commit, pipeline, merge request), last seen, every branch with its commits (linked to the repository when its address is known) and the recent pipelines.

### Fixed: last seen branch and commit, and the technique of trivy misconfigurations and secrets

- A finding seen again kept the branch and commit of its first sighting as "last seen" forever; they now follow the latest scan.
- A trivy report from `openctem-ci` names its capability in `metadata.properties`; ingest now reads it there, so the IaC job's findings are IaC instead of SCA. A report without a capability files trivy misconfigurations as IaC and secrets as secret detection by the finding's type. Migration 002215 relabels the existing misconfiguration and secret findings filed as SCA.
- A concurrent first sighting by a different tool no longer pairs that tool's version with the first reporter's name.
