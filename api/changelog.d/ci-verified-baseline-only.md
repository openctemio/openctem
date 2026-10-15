### Security: a CI job can no longer choose the branch its findings are compared with

- A pull or merge request run took its baseline from the `base_ref` the job reported at the exchange (every
  GitLab merge request, every push run, CircleCI, Bitbucket, Jenkins), and any branch named `release/*` or
  `main` qualified. A developer could push `release/x` with a vulnerability and name it as the base of a merge
  request: the finding counted as pre-existing and the new-findings-only gate passed. The reported `base_ref`
  is now ignored. The baseline is GitHub's signed `base_ref`, or a GitLab merge request's target branch read
  from GitLab through the organization's GitLab connection, and only when that branch is the default branch or
  protected; otherwise the default branch.
- **Behaviour change:** a branch typed `main` or `release` from its name no longer counts as exposure for
  baselines or for promoting branch-only findings to organization findings; only the default branch and
  protected branches (from repository import or set by an administrator) do. Findings already promoted stay
  promoted. Migration `002139_exposure_default_or_protected_only` replaces `branch_counts_as_exposure`.
- **Upgrade note:** to compare merge requests into a release line with that line, mark the branch protected
  (repository import reads protection from the code host) and, for GitLab, connect the group.
