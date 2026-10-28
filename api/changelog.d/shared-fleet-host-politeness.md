### Changed: shared sensors protect a target host across organizations

- A shared (platform) sensor job now starts only while fewer than two shared jobs of any organizations hold
  one of its hosts (one for intrusive work). Before, per-host politeness on the shared fleet was per
  organization only, so several organizations could scan one host from the platform's egress at once.
- The claim locks and counts the host across organizations and within its own batch. A waiting organization
  sees only that its job waits for its hosts, never who else scans them. Organization sensors keep
  per-organization host keys and are not affected (RFC-129).
