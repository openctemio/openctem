### Security: deleting a finding leaves an audit event

- `DELETE /api/v1/findings/{id}` hard-deletes the finding and, by cascade, its whole activity timeline, and wrote no audit record. It now writes an `audit_logs` event `finding.deleted` first (actor, title as the resource name, and metadata: severity, status, source, CVE, asset, fingerprint, tool, and the number of activity rows removed with it) and only then deletes. If the audit write fails the finding is kept and the request fails (fail closed). The audit log is the retained record; the activity timeline still goes with the row. Lookups stay tenant-scoped: another organization's id answers 404 and writes no event.
- Not changed: `DeleteAssetFindings` has no caller in the API (it is not user-triggered), so it is not audited here.
