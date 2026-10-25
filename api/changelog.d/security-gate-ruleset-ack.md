### Security: the security gate works with its workflow pinned by a ruleset

- The commit a `security-ack` label covers now comes from the head branch's push log (GitHub's own timestamps), not from a gate run started by the label: a ruleset-pinned gate workflow never starts on labels, so every acked pull request was blocked. Commit dates, workflow runs and check suites are never read; a push 60 seconds or less before the label, a missing log entry or an API error fails closed.
- New `security-gate-label.yml` re-runs the head's gate run when `security-ack` is added or removed or the pull request is retargeted. It decides nothing; fork pull requests are re-run by hand.
- The gate job no longer needs `actions: read`.
- **Upgrade note:** after this is on `develop`, set the "Security gate from develop" organization ruleset back to active (see the guide); a pull request can then no longer change its own gate.
