### Added: the suppression approval preview lists example findings within the approver's access

- `GET /api/v1/suppressions/{id}/preview` now also returns `in_scope_findings` and `sample`: how many of the matching open findings are on assets the caller's data scope covers, and the first 10 of them (title, severity, asset, path). `matching_open_findings` stays the organization-wide count the approval acts on; findings outside the caller's scope are counted there and never listed. The approve dialog shows the examples and how many matches are not listed (en and vi).
- The examples are listed only to a caller who also holds `findings:read`; the counts stay. A secret finding's title (its message can quote the secret) is never listed: its rule id and path identify it.
