### Fixed: every API error body carries the request id, and audit rows only get validated ids

- Error responses now include `request_id`, equal to the `X-Request-ID` response header, so a failed call can be matched to its log lines and audit rows.
- Audit rows no longer record the raw inbound `X-Request-ID` header: 57 handlers read it unvalidated, so a client could write arbitrary strings into audit entries. They now use the id validated (or minted) by the request-id middleware. A test fails on any new raw read.
