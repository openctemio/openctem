### Changed: the seed image is a psql client (114 MB to 9 MB) and runs as non-root

- `ghcr.io/openctemio/seed` is Alpine with the PostgreSQL 18 client and the
  seed files, instead of the full `postgres:18-alpine` server image (amd64:
  114.5 MB compressed with 1 CRITICAL and 24 HIGH advisories before, 8.9 MB
  with none after). It runs as uid 65532: psql needs no privileges.
- Usage is unchanged: `docker run --rm -e PGHOST=... ghcr.io/openctemio/seed:<tag> psql -f /seed/seed_required.sql`.
  The image no longer contains a PostgreSQL server or its entrypoint script.
