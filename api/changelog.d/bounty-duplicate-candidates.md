### Added: duplicate candidates with "known since" for triage

- `GET /api/v1/findings/{id}/duplicate-candidates` (`findings:triage`) suggests up to 20 findings that may describe the same issue: same asset or same host, sharing a CWE, a CVE or the vulnerable path, any source and status. Each carries its first detection; for a bug-bounty report the answer says whether the issue was known before the report was submitted (RFC-121).
- Candidates come only from the caller's data scope (and the pentest member rule); the finding itself must be in scope, and another tenant's id is 404. Nothing is merged automatically.
