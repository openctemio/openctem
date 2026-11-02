### Added: scan identification headers for the organization and the platform

- Organizations set up to 6 request headers with free names and values (for example `ATTT: is-here`) beside the existing scan User-Agent, in Settings > Scanning > Scan identification, with a live preview of what a target receives. Saved in the security settings (`tool_http_headers`; owner, step-up, audited).
- Platform administrators set an instance-wide User-Agent and up to 4 headers, each optionally enforced, in Console > System > Scan identification (`/api/v1/admin/settings/scan-identification`; step-up, reason, audited, administrators notified).
- The two layers merge (union; the organization wins a clash unless the platform enforces the header; bug-bounty program rules go over both) into the signed `http_policy` of every scan, retest and validate job. Retest and validate jobs now carry the organization's User-Agent and TLS setting too.
- Header names must be HTTP tokens; connection, proxy, `Host`, `Authorization` and `Cookie` headers and line breaks are refused. A job whose program headers would push it over 10 headers fails with `PROGRAM_RULES_CONFLICT`.
