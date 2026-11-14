# RFC-158: Held findings when the target throttled the scan

| | |
|---|---|
| Status | Accepted (2026-11-14). The verification state, holds from a command's coverage gaps, and the exclusions from scores, SLA escalation, notifications and tickets are shipped; holds the sensor sends with each finding (the CTIS hold field), automatic re-checks, the `not_reproduced` outcome and the console's held view are planned |
| Scope | server (finding state, ingest, scoring, SLA, notifications, tickets), sensor, CTIS |
| Architecture | [held-findings.md](../architecture/held-findings.md) |
| Related | RFC-074 (adaptive sensor control), RFC-093 (asset coverage), [scan coverage gaps](../architecture/held-findings.md#coverage-gaps) |

## 1. Problem

Scans that run faster than a target accepts get rate-limit, challenge and block pages back. Checks that match on
generic words, on a status code or on a response time then match those pages, and every match became a finding
that fed risk scores, SLA clocks, notifications and tickets. Measured on one installation: 43 % of template
findings were matched on a 403, 429 or 503 response, and a third of scan commands reported their target throttled,
blocked or unresponsive.

## 2. Decision

- A finding has a verification state: `unchecked` (default), `held`, `verified`, `not_reproduced`, and, when
  held, the codes behind it. Nothing is dropped: a held finding is kept with its evidence and listed.
- A held finding stays out of risk scores, SLA escalation, notifications and tickets until it is checked. One
  notice per hold names the held critical findings, so a real critical finding is never silent.
- A scan command whose result names a host in a throttling coverage gap (`throttled`, `blocked`,
  `edge_protected`, `rate_floor`, `catch_all`) holds the findings its reports sighted first on that host
  (`target_throttled`).
- A held sighting never downgrades a finding that existed before or was verified. A clean sighting releases a
  held finding.
- `not_reproduced` is never an automatic false positive.

## 3. Security

- Every hold query is pinned to the tenant on every table it reads (findings, reports, assets); a command or
  report id of another tenant holds nothing (tested).
- Holding is reversible and audited by the finding's state; a target cannot hide a real finding by serving block
  pages: the finding is kept, a critical one is announced, and automatic re-checks (planned) release it.
- The hold reasons are fixed codes (database CHECK), never target content.

## 4. Plan

Shipped: the state, holds from coverage gaps, the exclusions, the notice. Planned: the sensor's per-finding screen
(block pages, 429/503, timing and out-of-band checks) carried in CTIS, automatic gentle re-checks that set
`verified` or `not_reproduced`, and the console's held filter and counts.
