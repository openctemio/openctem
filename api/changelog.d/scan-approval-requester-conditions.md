### Added: scan approval rules by requester, origin and business hours

- Approval rule conditions `requester_roles`, `requester_group_ids`, `origins` (`ui`, `api_key`, `service_account`, `mcp`, `ci`, `system`) with `trusted_service_account_ids`, and `hours` (weekly windows in the organization's or a named timezone, catching scans outside or inside them; daylight saving follows the wall clock) (RFC-073 §4.1).
- The origin comes from the authentication method; a trusted service account is exempt only when it is one of the organization's service accounts. Unknown requester, origin or time is caught, and a failed lookup refuses the run.
