### Security: sensor authentication failures no longer log the error text

- The ingest, protocol v2 and v3 authentication paths logged the error of a failed sensor authentication at debug level; that error can carry material from the request's credential headers. They now log a fixed reason (`paused`, `bearer_on_v3`, `invalid_credentials`).
- fast-uri 3.1.8 to 3.1.9 in the web lockfile (CVE-2026-110306, CVE-2026-110180).
