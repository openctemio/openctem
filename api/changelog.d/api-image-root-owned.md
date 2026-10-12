### Changed: the API image is half the size and its files are read-only to the API

- `openctem-api` no longer stores every binary twice: the files are owned by
  root at copy time instead of a later `chown -R /app`, which duplicated the
  whole application in a new layer (amd64: 87.8 MB compressed / 250 MB
  unpacked before, 45.9 MB / 131 MB after).
- The binaries, OpenAPI spec, migrations and configs are owned by root, so the
  API process (uid 1000) can no longer modify its own code. The writable paths
  are unchanged: `/app/data` (attachments, sensor CA) for the API, and
  `/var/lib/openctem-signer` and `/run/openctem-signer` for the job signer.
- The four binaries are built in one `go build` with `-trimpath` (no builder
  paths in the binaries) and a BuildKit build cache.
