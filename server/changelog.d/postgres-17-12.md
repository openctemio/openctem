### Security: PostgreSQL 17.12 in CI and the release build

- PostgreSQL 17.12 (2026-11-12) is an upstream security release; it fixes CVE-2026-6460
  (authenticated arbitrary code execution, CVSS 8.8) among others. CI and the release image
  build now test against `postgres:17-alpine` at 17.12.
- **Upgrade note:** upgrade your PostgreSQL 17 server to 17.12 and restart it. No dump, restore
  or data migration; rebuild any third-party C extensions you added. With the Compose stack
  (`postgres:17`): `docker compose pull postgres` then `docker compose up -d postgres`.
- Docs: https://docs.openctem.io/operations/upgrade/#security-advisories-database-patch-releases
