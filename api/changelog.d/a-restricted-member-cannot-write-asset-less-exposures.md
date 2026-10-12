### Security: a restricted member cannot write asset-less exposures

- `POST /exposures`, `POST /exposures/ingest` and the bulk ingest refuse an
  exposure without `asset_id` from a member whose data scope is restricted
  (400 `asset_id is required`; a bulk item is reported and dropped). An
  asset-less exposure is in nobody's asset scope (owner decision D11), and the
  fingerprint upsert let a restricted member overwrite an existing asset-less
  exposure's severity, title and details, e.g. downgrade a critical one
  (research 21b H1, RFC-050 W1). Administrators, full-data roles, sensors and
  internal jobs are unchanged; out-of-scope asset ids were already refused.
