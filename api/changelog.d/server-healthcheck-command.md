### Added: `server -healthcheck` for container healthchecks without a shell

- `server -healthcheck` requests `GET /health` on `127.0.0.1:$SERVER_PORT`
  (default 8080), with no proxy, no redirects and a 3 s timeout. It exits 0
  on a 200 answer and 1 otherwise.
- The API image's `HEALTHCHECK`, `api/deploy/docker-compose.yml` and the e2e
  Compose file use it instead of `wget`, so the API image will no longer need
  busybox. The probe can only reach the container's own loopback listener.
- Upgrade note: the Compose healthcheck now needs an API image from this
  release or later. An older image does not know the flag and reports
  unhealthy, so keep the Compose file and the image on the same release.
