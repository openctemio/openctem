### Security: a campaign's finding filter can no longer widen to the whole organization

- A campaign's `finding_filter` is parsed strictly: an unknown key, a value of
  the wrong type or a value that does not parse is refused with 400 on create
  and update. Before, such a condition was dropped:
  `{"asset_id":"bad","severity":"critical"}` covered, and resolved, every
  critical finding of the organization.
- A status alone (`{"statuses":["new"]}`) is no longer scope: such a campaign
  tracks nothing and cannot resolve. A stored filter that no longer parses
  tracks nothing and its resolve answers 400 until the scope is edited.
- `POST /api/v1/remediation/campaigns/{id}/resolve` now needs
  `findings:fix_apply` as well as `findings:remediation:write`, and works only
  on an `active` or `validating` campaign.
