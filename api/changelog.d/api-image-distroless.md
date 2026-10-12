### Changed: the API image is distroless (no shell, no busybox)

- `openctem-api` is built on `gcr.io/distroless/static-debian13:nonroot`. It
  contains the four binaries, the OpenAPI spec, migrations, configs, CA
  certificates and time zones, and nothing else: no shell, no busybox
  `wget`, no package manager (42.7 MB compressed, amd64).
- Users, uids, paths, writable directories and the entrypoint are unchanged
  (`USER` is now numeric, `1000:1000`).
- Healthchecks use the binaries themselves: `server -healthcheck` for the API
  and the new `openctem-signer healthcheck` (connects to the signer socket)
  in `docker-compose.job-signer.yml`, replacing `test -S`.
- Debugging: there is no shell to `docker exec` into. Use an ephemeral debug
  container (`docker debug <container>`, or
  `kubectl debug -it <pod> --image=busybox --target=api`) or run the image's
  binaries directly (`docker run --entrypoint /app/bootstrap-admin ...`).
