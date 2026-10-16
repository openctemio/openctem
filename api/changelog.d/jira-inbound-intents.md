### Added: Jira status changes follow the published mapping profile

- When a Jira project has a published finding mapping profile, its inbound
  status rules decide what a status change means: Done is a fix claim
  (verification queued), In Progress starts work, and "Won't Do" (or the
  resolution the profile names) opens a pending risk-acceptance or
  false-positive request. A request is made by the linked ticket, never by a
  person, and a person with the approve permission decides it; an
  in-progress finding goes back to confirmed first. The issue gets one comment
  saying what was requested or refused. A ticket still never closes a finding.
- Approvals list a ticket's request as "Linked ticket".
