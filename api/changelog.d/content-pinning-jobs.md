### Added: jobs pin the content they read, and shared sensors fetch platform packs

- Shared sensors may read the content routes in a platform-only scope: the platform's `stable` packs, one copy for all organizations. An organization's pack is `404` for them and never reaches a shared sensor. RFC-061 §3.7 is amended to match.
- The heartbeat answer carries `content_version` (the ETag of the sensor's desired set), the pairing identity carries `content_signing` (the platform key, and the organization's key for its own sensors), and the heartbeat's `local_store.content` (held digests and counters) is stored with the sensor's report.
- Scan and retest jobs pin content at claim time: the platform sets `content[]` (packs by digest) and `inputs[]` (lists generated from the organization's own names) on the sensor's copy of the command, the signed statement lists each pack's `{slot, digest}`, and every digest is checked to be deliverable to the job's organization before it is signed. A job asks for a wordlist with a `wordlists` payload member; depth picks the class (standard S, deep M).
- The signer validates the statement's `content` member (`bad_content` refusal).

### Removed: unused custom wordlist reference on tool configurations

- `tenant_tool_configs.custom_wordlists` was stored and never read; wordlists are content packs of kind `wordlist`. The column is dropped.
