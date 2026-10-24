### Security: audit-log write failures are no longer silently dropped
- 32 call sites discarded the error of an audit write (`_ = svc.LogEvent(...)`); they now go through `audit.RecordOrWarn`, which logs a WARN with the action, resource and a sanitized error. API key create/revoke/delete, credential create, failed login and logout log the same way.
- Deleting a suppression rule now writes its audit row first and refuses to delete when the row cannot be written.
- A guard test (`TestNoDiscardedAuditWrite`) fails the build when production code discards the error of `LogEvent`, a typed `Log*` audit helper or `RecordAudit`.
