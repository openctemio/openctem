### Security: automatic signals flag a decision for review instead of reversing it

- A changed taint source no longer reopens a false-positive or accepted
  finding, and an indicator-of-compromise match no longer reopens a false
  positive, an accepted risk or a duplicate. The decision stands; a review
  flag is raised (`finding_decision_reviews`, reasons `taint_source_changed`
  and `ioc_match`) with a `decision_review` timeline entry and an audit event,
  for a person with the approve permission to decide. The flag clears when the
  finding's status changes.
- An IOC match still reopens a finding closed as resolved.
- Migration `002154` adds the table, the clearing trigger and the
  `decision_review` activity type.
