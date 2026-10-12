### Fixed: import uploads honour their documented size limits

- The web console now streams import uploads to the API instead of reading
  them into memory, up to each route's own limit: finding import 110 MiB,
  SBOM import and asset CSV import 50 MiB, campaign Burp/CSV import 50 MiB.
  Before, every upload above 12 MiB was refused by the console although the
  finding import accepts 110 MiB. Other requests keep the 12 MiB cap.
- `POST /components/import`, `POST /assets/import/csv` and
  `POST /pentest/campaigns/{id}/findings/import` declare their body limit on
  the route, which replaces the global 10 MiB limit (`SERVER_MAX_BODY_SIZE`).
  Before, they refused every file above 10 MiB although they document 50 MiB.
  The permission gate still runs before any of the body is read.
- Multipart forms (attachments, campaign import, credential CSV import) keep
  at most 1 MiB in memory; larger file parts are spooled to a temporary file.
