### Documentation: RFC-055 covers web scope, CTIS 1.6 endpoints and evidence

- RFC-055 and `docs/architecture/tool-contract.md` now describe:
  - the job's `web_scope` and how the SDK and katana enforce it;
  - the `endpoint` record kind and port;
  - CTIS 1.6 `endpoints[]`, `finding.web` and `finding.evidence_items` with marked sensitive spans;
  - retest verdict evidence and the rule that a networked `fixed` needs the attempt's HTTP exchange.
- The RFC index row lists the merged and open pull requests.
