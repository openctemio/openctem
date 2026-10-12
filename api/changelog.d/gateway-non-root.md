### Behaviour change: the Compose gateway runs as non-root from the openctem-gateway image

- `api/deploy/docker-compose.yml` runs the gateway from
  `ghcr.io/openctemio/openctem-gateway` (Caddy with the standard and layer4
  modules, built with the release's Go) as uid/gid 1000, with no capability
  and `no-new-privileges`. It binds 443 through the namespaced sysctl
  `net.ipv4.ip_unprivileged_port_start=0`. Before, it ran as root from
  `caddy:2.11.4-alpine`. The image is set with `GATEWAY_IMAGE` /
  `GATEWAY_VERSION` (default: `OPENCTEM_VERSION`).
- Upgrade: the new one-shot `gateway-init` service changes the owner of the
  `gateway-data` / `gateway-config` volumes and `./ca` to 1000:1000 before
  the gateway starts, so `docker compose up -d` keeps certificates, the
  internal CA and the ACME account. Without it, run once:
  `docker compose run --rm --no-deps --user 0 --entrypoint chown gateway -R 1000:1000 /data /config /ca`.
  The gateway refuses to start on root-owned data and prints that command
  (`api/docs/deployment/docker.md`, "Gateway user").
- The `openctem-gateway` image itself now runs as uid 1000.
