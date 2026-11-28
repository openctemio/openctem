### Security: the vulnerability feed address test is audited and answers less

- `POST /api/v1/admin/settings/vulnfeed-sources/test` now writes a high admin audit row (`platform.vulnfeed_sources_tested`) for every test, refused or not, with the administrator, the addresses asked for and the outcome per address.
- Each address answers verified or one of `blocked_address`, `not_verified`, `not_configured`; `not_found`, `http_error`, `root_mismatch`, `pointer_invalid`, `unreachable` and `http_status` are no longer returned, so the test no longer tells which public hosts answer and with what status. The precise cause goes to the server log.
- Docs: server/docs/architecture/feed-transfer.md
