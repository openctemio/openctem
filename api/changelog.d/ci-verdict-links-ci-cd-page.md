### Changed: CI gate verdicts link to the run on the CI/CD page

- The `links.run` URL of a gate verdict (printed by the CI job) and the
  break-glass notice now open `/ci-cd?view=runs&run=<run id>` directly instead
  of the retired `/ci-runners/<run id>` path.
