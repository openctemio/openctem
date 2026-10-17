### Added: Jira status changes follow the published mapping profile

- When a Jira project has a published finding mapping profile, its inbound
  status rules decide what a status change means: Done is a fix claim
  (verification queued), In Progress starts work, and "Won't Do" (or the
  resolution the profile names) opens a pending risk-acceptance or
  false-positive request. A request is made by the linked ticket, never by a
  person, and a person with the approve permission decides it; an
  in-progress finding goes back to confirmed once its request exists (it
  stays in progress when a request is already pending or cannot be made). The issue gets one comment
  saying what was requested or refused. A ticket still never closes a finding.
- A Jira status change of an issue outside the projects configured for
  ticketing moves no finding (the same rule as linking an existing issue).
- Approvals list a ticket's request as "Linked ticket".
