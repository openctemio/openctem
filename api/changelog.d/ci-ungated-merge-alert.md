### Added: an alert when a pull request is merged without a passing CI gate

- When a default-branch run on GitHub comes from a merged pull request whose
  last OpenCTEM gate verdict was not a pass (or that was never judged), the
  notification event `ci.ungated_merge` is sent (high, once per run;
  migration `event_type_ci_ungated_merge`). It needs the GitHub App
  installation that posts the check; it tells you a merge did not wait for the
  gate, typically because the check is not required in branch protection.
