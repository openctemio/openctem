### Fixed: the gate check and pull request comment are no longer lost or marked final too early

- Storing a run's verdict queues its GitHub or GitLab decoration in the same
  statement. Before, a failure of a later step left the verdict without a
  check, and branch protection waited for one forever.
- A failed post is retried up to eight times with a backoff (30 seconds,
  doubling, at most 30 minutes apart). Before, five attempts ran within about
  75 seconds. A GitHub rate limit (429, or 403 with Retry-After or no
  requests left) is retried instead of being final.
- When GitHub recomputes a pull request's merge commit because the base
  branch moved, a run that judged the same head (one of the merge commit's
  parents, as GitHub reports them) still posts its check on the head.
  Before, it was skipped as "newer commits".
- The check is `action_required` when only a scanner failure failed the gate.
  Findings the policy lists in comment mode are notice annotations, marked
  "not blocking" in the comment.
