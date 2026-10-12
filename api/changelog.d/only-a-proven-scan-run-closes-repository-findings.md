### Behaviour change: only a proven scan run closes repository findings

- **Default-branch auto-resolve needs a clean, bound run** (research 18 F3,
  owner decision O11). A scan closes a repository finding only when a
  protocol v2 run **bound to a command** completed with exit code 0, every
  report of the run completed with nothing rejected, quarantined or in error,
  the reports are an explicitly `full` scan of the default branch, and the
  finding was last seen by the same tool **under the same scan profile**
  (the blinding guard still applies). Before, any full default-branch report
  closed what it left out, even when the scanner had failed or ran a
  narrower ruleset.
- **Never closes now:** a report without a command (CI runner or collector,
  also in `warn` mode), a tenant upload (SARIF, CTIS, Nessus) and any
  protocol v1 report. They still create and update findings, and the
  per-branch occurrence sweep is unchanged. Findings they leave open close on
  the next clean bound run that saw them, by retest, or by a
  `findings:verify` holder.
