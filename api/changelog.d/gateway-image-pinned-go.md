### Changed: the layer4 gateway image is built with the pinned Go and ships one Caddy binary

- `api/deploy/gateway/Dockerfile` (the `openctem-gateway` image with the
  layer4 module) compiles Caddy v2.11.4 and caddy-l4 v0.1.2 with the pinned Go
  toolchain and current `golang.org/x/net` and gRPC, on plain Alpine laid out
  like the Caddy image (`/config`, `/data`, `/etc/caddy`, `/srv`, the same
  command and ports). Before, it replaced the binary of the Caddy image, so
  both binaries shipped, and Caddy's build toolchain carried 10 HIGH
  advisories: amd64 39.7 MB compressed / 109 MB unpacked with 10 HIGH before,
  22.6 MB / 63 MB with none after.
