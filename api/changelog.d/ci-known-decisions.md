### Added: CI jobs learn which of their results are already decided

- The CI results upload answers with `known`: the results of that report marked false positive, duplicate, accepted risk (unexpired) or covered by an approved suppression rule, by index. The CI CLI leaves them out of its console, SARIF and merge request report. A job learns nothing about findings it did not report.

### Fixed: an approved exception covers the finding it was requested for

- The CI gate applies approved, unexpired suppression rules when it judges a run, so a rule approved after the finding was first seen (an `.openctem.yml` exception) no longer leaves that finding counting. Ingest still stamps only new findings; the gate decision is read only.
