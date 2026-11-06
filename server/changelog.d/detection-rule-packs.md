### Added: detection rules for web fingerprints and exposed secrets

- Two new kinds of signed platform content pack, `web-fingerprints` and `secret-rules`, run by the platform on the web content each report already carries (URL, final URL, title, `Server` header, cookie names, favicon hash, script paths), before anything is stored. No sensor change.
- Fingerprint matches become asset technologies with a version, category and CPE (source `rules:<pack>@<version>`); versioned products also become software components for CVE matching. A tool's own report of the same technology wins.
- Secret matches (keys, tokens, private keys, credentials in URLs, internal host names, debug output) become `credential_leaked` or `sensitive_data_exposed` exposures holding only a keyed fingerprint, a short preview, the length and the location; the value is never stored or logged.
- Built-in packs `web-fingerprints-core` and `secret-rules-core` (release 2026.10.1) are installed on first start when no stable channel of that name exists.
- Organizations manage their own rules under `/api/v1/content-rules` (`scans:content:read` / `scans:content:write`): validated RE2 patterns with keyword prefilter and size limits, versioned, audited, at most 200, with a masked test against a pasted sample.
- Every command-bound report records the rule packs it was matched with in its command's content pins (`rules`).
- Migration 20261031090033 adds `tenant_content_rules`.
