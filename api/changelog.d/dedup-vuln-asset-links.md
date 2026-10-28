### Added: the same CVE on one asset from different techniques is linked as one issue

- A version match, a template check (nuclei and similar), a network scanner import and a package inventory that report the same CVE on the same asset, on agreeing ports, are linked as the same issue (rule `vuln_asset`), not merged. The earliest finding is the original and is never demoted; no status, severity or SLA changes; the dashboard counts the group once.
- An open template check or network scanner report confirms a version match in its group: the "potential" P2 cap is lifted and the finding counts on the attack path again.
- A new finding that joins the group of an open original raises no second "new finding" notification, unless it is more severe than the rest of the group.
- Migration 003505 adds the key kind, the locator column, the rule and the timeline entry type; 003506 validates the widened activity type check without blocking writes. **Upgrade note:** run `refingerprint -links` (dry run first, then `-apply`) to link findings that already exist.
