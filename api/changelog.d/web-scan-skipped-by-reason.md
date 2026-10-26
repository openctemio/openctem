### Changed: the New Scan review and the run's Dispatch card show skipped targets by reason

- The review's block is now "What this scan covers": how many targets the scan takes, then every skipped target grouped by reason with the fix. Each group opens to a searchable list. Typed targets can be removed from the scan in one click. An expected reason (names with no DNS answer, scope exclusions) is neutral, a reason that needs a fix is amber, and nothing is red.
- The block shows for teams without scan zones too. The zone picker, zone table and zone wording appear only when the team has zones and targets go to them.
- The run's Dispatch card uses the same block and the same zone table.
- Targets, dynamic options: "Include names that do not resolve" (`target_options.include_unresolved`).
- Every string in the routing preview and the Dispatch card is translated (en, vi).
