### Fixed: remediation suggestions no longer group findings by boilerplate advice

- Remediation keys record the version of the key rules that derived them. The suggestion generator re-derives a tenant's keys before a run when any key is older, and never uses a stale key; keys from the first rules (which hashed any solution text) no longer form suggestions such as "Apply the suggested fix code." over unrelated findings. Open suggestions built on those keys expire on upgrade.
- A solution text groups only by its specific sentences (a version or an advisory id); code and configuration findings group by solution text only within one scanner rule.
- Suggestion confidence is computed from the members (one rule, one vulnerability) instead of a constant per key kind, and the factors behind it are stored with the suggestion (`fix_spec.basis`, `fix_spec.rule_ids`).
