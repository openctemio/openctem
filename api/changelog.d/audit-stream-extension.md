### Removed: off-box administrators' audit stream leaves the Community build

- Streaming the administrators' audit log to an external destination (`ADMIN_AUDIT_SINK`, `ADMIN_AUDIT_SINK_SECRET`, `ADMIN_AUDIT_SINK_SYSLOG_*`, `ADMIN_AUDIT_SINK_HEAD_INTERVAL`) is now provided by an extension, no longer by the Community build. The audit hash chain, its verification, the hourly chain check and every audit view and export stay. The table `admin_audit_forward_cursor` stays in the schema; no migration.
- Moved now rather than after a notice period: no outside installation uses the stream yet.
- **Upgrade note:** a server refuses to start while one of these settings is set and no extension of its build declares it; unset it, or run a build that includes the stream. With `MANAGED_SERVICE=true` in production the Community build no longer requires a stream.
