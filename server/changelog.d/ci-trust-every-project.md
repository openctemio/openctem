### Added: a CI trust configuration for every project of a self-managed GitLab

- `rules.all_repositories` ("Every project on this GitLab") accepts CI results from any project of a self-managed GitLab without naming its top-level groups. It is refused for gitlab.com and every other shared issuer, where it would admit anyone's projects.
- A project seen for the first time is a new repository: listed by top-level group and, by default, refused with `CI_TOKEN_REPOSITORY_PENDING_APPROVAL` until an administrator approves the project or its whole group (the group then joins the configuration's owners, so its future projects need no approval). Blocking a project or group refuses it with `CI_TOKEN_REPOSITORY_BLOCKED`, reversibly. Optional `admit_new_repositories` imports a new project's results while it waits. Only approved projects reach scope.
- New configurations of this kind start with protected branches and tags only and a notice when a new group asks (in the app and on channels subscribed to the new event `ci.new_repository_group`).
- API: `GET /api/v1/ci/trust-configs/{id}/new-repositories` and `POST /api/v1/ci/trust-configs/{id}/new-repositories/decisions` (CI write permission; decisions need a recent sign-in and are audited). Migration `20261118080035_ci_trust_new_repositories`.
- Docs: server/docs/how-to/gitlab-ci.md#every-project-on-this-gitlab
