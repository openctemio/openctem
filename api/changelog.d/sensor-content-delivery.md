### Added: content delivery to sensors by digest (research/139 P0)

- New sensor routes under `/api/v2/sensor/content`:
  - `desired`: the organization's active packs, the platform's stable packs, and the revoked digests. It has an ETag; `If-None-Match` answers 304 with no body.
  - `packs/{digest}`: the canonical archive, immutable, with Range support.
  - `packs/{digest}/index`: the pack's files.
  - `packs/{digest}/files/{sha256}`: one file, so a sensor fetches only the changed files of a new version.
- A sensor reads only digests in its organization's desired set; anything else is `404 content-not-found`. A revocation takes effect within 10 seconds.
- Measured with 3 sensors over 2 runs: a new pack version with 2 of 40 files changed cost 92% less traffic than full downloads.
