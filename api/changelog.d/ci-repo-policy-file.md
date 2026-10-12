### Added: a repository's .openctem.yml can tighten the CI gate and request exceptions

- `POST /api/v1/ci/runs/{id}/evaluate` takes `repo_policy` (the gate part of
  the repository's `.openctem.yml`, sent by the runner). Its values apply only
  when stricter than the organization's policy (`fail_on_severity`,
  `new_findings_only: false`, `fail_on_kev: true`, `epss_threshold`,
  `block_rules`); an invalid file is refused. The verdict says
  `repo_file: applied` or `ignored`.
- `exceptions` (rule, optional path, reason, expiry within 90 days) become
  pending suppression requests on the repository, from default-branch runs
  only and once each (audited `ci_run.exceptions_requested`); they apply only
  after an administrator approves them.
- A gate policy with `allow_repo_policy: false` makes the platform ignore
  repository files (any applicable policy saying no wins). Migration
  `ci_gate_policy_allow_repo_policy`.
