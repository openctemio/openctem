### Added: a decision on a taint finding is suspended when its source changes

- A false-positive or accepted taint finding whose re-scan reports another source (file and code of the trace's source step) is confirmed again for review; the earlier decision is kept (`finding_decision_suspensions`) and the change audited. A refactor of the steps in between, or a trace-less report, keeps the decision. The trace is never part of the finding's identity.
