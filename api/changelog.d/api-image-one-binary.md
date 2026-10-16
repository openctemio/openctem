### Changed: the API image's operator commands are links to the server binary

- `bootstrap-admin`, `refingerprint`, `repomerge` and `ci-trust-scope-plan` in
  the `openctem-api` image are now links to `/app/server`, which runs the
  command named by the link. Each was a static binary that linked most of the
  API (17-26 MB each); the image drops from 175 MB to about 97 MB unpacked,
  and the all-in-one image drops its second copy of `bootstrap-admin`.
- Paths, flags and output are unchanged: `docker compose exec api
  /app/bootstrap-admin ...`, `docker run --entrypoint /app/repomerge ...` and
  `go run ./cmd/<command>` work as before. The job signer stays a binary of
  its own.
