### Added: CTEM-ID code on exposures, derived from our own data

- Exposures carry `ctem_id {code, catalog_version, basis, url}` when their type, details and linked asset settle a CTEM-ID code (catalog 1.0; 9 of 29 codes derivable today: lookalike domains by technique, publicly dumped credentials of the organization or a vendor, internet-facing systems by asset scope or type, vendor public repositories). No code is shown when the data does not settle one. The exposure detail shows the code linked to its ctem.org page. See `docs/architecture/ctem-id-mapping.md`.

### Removed: CTEM-ID catalog download and the manual exposure tag

- The daily `ctem-id-refresh` job, `CTEM_ID_FEED_URL`, `GET /api/v1/ctem-ids` and `PUT /api/v1/exposures/{id}/ctem-id` are removed. The platform makes no request to ctem.org.
- The exposure response's `ctem_id` changes from a free-text string to the object above.
- Migration `20261102020530_drop_ctem_id_catalog` drops the `ctem_id_catalog` table (a downloaded copy of public reference data; no tenant data).
- **Upgrade note:** remove `CTEM_ID_FEED_URL` from the environment if set (it is ignored).
