### Added: bug-bounty program rules travel with every job

- A program can state testing windows (`rules.testing_windows`: days, start, end, IANA time zone; at most 14). RFC-065 §12.
- When a sensor polls or claims a job whose targets a program covers:
  - outside the program's testing windows, the job is not handed out; it stays queued and leaves when a window opens;
  - programs whose rules conflict (two values for one header, two User-Agents) fail the job with `PROGRAM_RULES_CONFLICT`;
  - otherwise the delivered job carries the program's identification headers and User-Agent in `http_policy`, and its `rate_limit` is capped at the smallest program rate. The stored job is unchanged.
- A job with program headers or a User-Agent goes only to a sensor built with SDK v0.19.0 or later; older sensors do not get it.
- Triggering a scan refuses, up front, targets outside a program's testing windows (`PROGRAM_OUTSIDE_WINDOW`) or covered by programs whose rules conflict (`PROGRAM_RULES_CONFLICT`).
- A program can no longer require credential or connection headers (`Authorization`, `Cookie`, `Host`, `Proxy-*`, and similar).
