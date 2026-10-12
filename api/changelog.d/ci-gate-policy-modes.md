### Added: block, comment or monitor per capability and rule in CI gate policies

- A gate policy takes `modes` (`POST`/`PATCH /api/v1/ci/gate-policies`):
  `{"capabilities": {"sast": "comment"}, "rules": {"<rule id>": "monitor"}}`.
  `block` fails the gate as before, `comment` lists the finding on the verdict
  (reason `mode: comment`) without failing, `monitor` only counts it
  (`summary.monitored`). A rule's mode wins over its capability's; anything
  unset blocks; a new secret always blocks. Rolling out a ruleset in comment
  mode no longer breaks builds. Migration `ci_gate_policy_modes`.
