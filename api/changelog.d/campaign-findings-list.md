### Fixed: a remediation campaign page lists the findings its count counts

- New `GET /api/v1/remediation/campaigns/{id}/findings` (remediation:read and findings:read): the findings the campaign tracks, from its finding filter, remediation key or linked findings, any status, on the caller's in-scope assets. Its total equals the campaign's `finding_count` for the same caller.
- The campaign page lists those findings, so a campaign scoped by a filter or a remediation key no longer shows "Findings (0)" next to "8 findings linked" in the list. Unlink is offered for explicitly linked findings only.
