### Security: a CI run over the 100,000-finding cap fails its gate instead of judging a prefix

- A CI run records at most 100,000 findings for its gate. A run that reported more used to be judged on the
  first 100,000 only, so a blocking finding past the cap was missed and the run could pass. It now fails with
  the reason `too_many_findings` ("Too many findings to judge" on the CI/CD page), and the findings are still
  stored on the platform. Repeating sightings the run already recorded does not count as overflow.
- Migration `002138_ci_run_findings_over_cap` adds `ci_runs.findings_over_cap` (boolean, default false; no
  table rewrite).
