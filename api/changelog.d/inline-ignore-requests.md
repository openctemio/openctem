### Security: inline ignore comments and ignore files no longer hide findings

- With the CI CLI that runs semgrep and opengrep with `--disable-nosem` and `--x-ignore-semgrepignore-files`, a result marked by an inline ignore comment or excluded by `.semgrepignore` is reported and counted by the gate. From a verified default-branch run each such claim becomes a pending suppression request for the security team (90 days), so approved ones then stop counting.
- Suppression requests that no user made (`.openctem.yml`, inline comments, ignore files) record the CI identity in the new `requested_by_actor` and a `created` audit row; the console shows the requester.
