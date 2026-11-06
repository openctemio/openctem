### Added: the administrators' audit chain report carries the chain head

- GET /api/v1/admin/audit-logs/chain and bootstrap-admin verify-audit (text and -json) now include the chain head (position and hash of the newest row, or of the newest anchor when no row is online) in every edition, so a copy of the log can be verified offline and compared with an earlier copy without a forwarding sink.
