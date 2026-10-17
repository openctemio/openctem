### Added: Dry run for adding existing CI trusts' repositories to scope

- CI trusts saved before "Trust and add to scope" existed keep it off. Nothing adds their repositories automatically: an administrator who may change scope turns it on per trust. That change is audited and the entries follow the organization's approval rules.
- New read-only command `ci-trust-scope-plan` in the API image, per tenant and in total:
  - what turning it on would do for those trusts (entries to create, or equal entries to link);
  - what the trusts that already manage scope would change (create, link, keep, retire, entries a person removed);
  - the patterns the platform would refuse.
- It runs on a read-only connection, so it is safe on a live database: `docker compose exec api /app/ci-trust-scope-plan` (`-tenant <id>`, `-json`).
