### Changed: the all-in-one image is 30% smaller, its gateway is built with the current Go, and the sensor CA persists

- `ghcr.io/openctemio/openctem` copies the web and API files in once, owned by
  root, instead of `cp -a` + `chown -R`, which stored the web console twice and
  then the web console and API a third time (amd64: 197 MB compressed / 642 MB
  unpacked before, 138 MB / 423 MB after). The runtime user can no longer
  modify the application; `/data`, `/config` and the Next.js cache stay
  writable.
- The runtime base is plain Alpine with node copied from the web image (no
  npm), instead of the node image.
- Caddy (same release, v2.11.4) is compiled with the pinned Go toolchain and
  current `golang.org/x/net` and gRPC instead of copying the released binary,
  which carried an older Go standard library: 20 HIGH advisories fewer in the
  image scan.

### Fixed: the all-in-one image keeps its sensor CA on the data volume

- `SENSOR_MTLS_CA_DIR` now defaults to `/data/sensor-ca` in the all-in-one
  image. Before, the CA the API mints for sensor mutual TLS was written inside
  the container filesystem, so a re-created container (an upgrade) minted a
  new CA and every sensor's client certificate stopped being trusted.
