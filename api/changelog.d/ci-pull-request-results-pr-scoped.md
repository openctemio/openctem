### Security: GitHub pull request results are recorded on the pull request, never on a real branch

- A GitHub pull request run recorded its findings on its head branch's name. A pull request from a branch named
  like a real one (a fork's `main` in a private repository that sends tokens to fork pull requests, or
  `release/1.x` into `main`) wrote its findings into that real branch, which later pull requests are compared
  with: a later pull request with the same finding passed as "pre-existing". Results now go to `pull/<n>`, as
  the other providers already did (GitLab keeps `merge-requests/<n>`); every pull or merge request upload is
  forced onto its own scope whatever branch name a stored run carries.
- Existing branch rows and occurrences are not moved.

### Behaviour change: a GitHub pull request run's branch is `pull/<n>`

- The CI/CD runs list shows `pull/<n>` for a GitHub pull request instead of its head branch. A trust
  configuration's `refs` rule no longer matches a pull request by its head branch name (a name the author
  chooses); list `refs/pull/*` to admit pull requests by ref.
