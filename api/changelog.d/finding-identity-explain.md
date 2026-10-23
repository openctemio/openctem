### Added: why a finding is one finding

- `GET /api/v1/findings/{id}/identity` (`findings:read`) explains a finding's identity: the recipe of its key (`v2/sca`, `v1/ingest`, `manual/v1`, `pentest/v1`, …), the names of the fields the key was built from, the tools that reported it, and the duplicates merged into it. The finding must be in the caller's data scope (404 otherwise); merged duplicates on assets outside the caller's scope are not listed or counted. Field names only: no key, fingerprint or field value is returned.
- The finding detail (overview tab and drawer) shows it as "Why this is one finding", in English and Vietnamese.
- Migration `003351_findings_identity_explain` adds the nullable columns `findings.identity_algo` and `findings.identity_fields` (no table rewrite, no backfill). Every keying now records them; rows keyed earlier are explained from the stored identity tuple, or shown as a legacy key.
