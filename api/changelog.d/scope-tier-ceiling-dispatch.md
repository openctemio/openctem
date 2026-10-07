### Behaviour change: a scope entry's tier ceiling is enforced on every dispatch; intrusive workflow steps need proof

- A scope entry authorizes probes up to its `max_tier`; a root-domain seed or
  verified domain up to t1 (RFC-054 §4.2). A target covered only below the
  probe's tier is now refused with `tier_exceeds` everywhere: scan create and
  quick scan answer `TARGET_OUT_OF_SCOPE` (fix `raise_tier` with the entry's
  id and the needed `tier`), a scan run leaves the target out with a warning
  (`TIER_EXCEEDS` when nothing is left), a workflow step leaves it out of that
  step, and pipeline runs, chained hops, coverage, validation and
  `POST /scope/check` refuse it. The probe's tier is the tool's highest stage
  tier (`zap` t2; `nuclei`, `httpx`, `naabu` t1; discovery and code tools
  t0); a tool the catalog does not know counts as t1.
- A workflow step whose tool is intrusive (t2) is handed only the run's
  targets at or under a verified domain; with none left it fails with
  `STEP_TARGETS_REFUSED` before any sensor sees it (RFC-054 §8.1).
- **Upgrade note:** existing entries are t1, so nothing changes for them. An
  entry an approver set to t0 now authorizes passive discovery only; raise it
  to t1 in Scoping > Targets to keep active scans of its names.
