### Fixed: a finding is only closed as fixed by a version change after the new version was evaluated

- When the inventory reported another version of a product, the matcher could close the finding as fixed before the new version had been checked against the CVE's ranges. A version that was still affected then reopened the finding on a later pass: a false fixed close on the timeline, a reopened finding, and a restarted history.
- The close now waits until the new version has been evaluated. If the new version is still affected, the one finding stays open (no close, no reopen) and records the version it is observed on. If it is fixed, the organization's closing mode applies as before (close, ask a person, or keep).
- A version that was never evaluated keeps its finding open: a missing match is not proof of a fix.
