### Security: a CI repository name stays with the repository that first reported under it

- CI trust rules match GitHub and GitLab owners and repositories by name. A
  name can change hands: an organization or group renamed or deleted and its
  name registered by someone else, or a repository deleted and created anew.
  The exchange now binds a repository name to the immutable repository id
  that first reported under it (GitHub `repository_id`, GitLab `project_id`;
  Bitbucket already did this), so a different repository under the same name
  cannot report into the repository asset. It is refused and audited
  (`ci_run.token_refused`, rule `repository_binding`) until an administrator
  retires the old pipeline. A rename keeps the id and is admitted.
