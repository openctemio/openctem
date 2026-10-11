### Added: the OpenCTEM gate as a GitLab commit status and merge request note

- An organization connects a GitLab group with a group access token
  (`POST /api/v1/ci/scm-apps/gitlab`, `scans:ci:write` and a fresh second
  factor; `DELETE /api/v1/ci/scm-apps/gitlab/{id}`; listed without the token in
  `GET /api/v1/ci/scm-apps`). OpenCTEM checks with GitLab that the token is
  active, has the `api` scope and belongs to a direct member of the group, and
  stores it encrypted (table `scm_gitlab_connections`, migration
  `scm_gitlab_connections`; covered by `cmd/rekey`).
- After a GitLab run's verdict the platform sets the commit status
  **OpenCTEM gate** (`success` or `failed`) and keeps one note on the merge
  request, updated in place; for a merge request only when the run's verified
  commit is its current head. Steps in
  `docs/how-to/gitlab-merge-request-feedback.md`.
- Without a GitHub App, GitHub runs are skipped and GitLab posting still runs.
