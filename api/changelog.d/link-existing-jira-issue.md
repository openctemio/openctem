### Added: link an existing Jira issue to a finding

- On a finding, "Link an existing issue" takes an issue key or its URL. The
  issue must be on the organization's Jira site and visible to the
  integration (a URL on another host is refused before any call); a moved
  issue is linked under its current key. Only issues in a project the
  organization configured for ticketing (the default project, a routing
  rule's project or a mapping profile's project) can be linked, so the
  platform never transitions or comments on issues elsewhere that the
  integration's account happens to see. Unlinking leaves the issue alone.
  `GET/POST /api/v1/findings/{id}/ticket-links`,
  `DELETE /api/v1/findings/{id}/ticket-links/{link_id}` (`findings:read` /
  `findings:write`, the finding's data scope), audited as
  `finding.ticket_linked` / `finding.ticket_unlinked`.
- Creating a ticket also records its link.
