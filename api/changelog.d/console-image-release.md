### Added: the platform console image is released and runs in the all-in-one image

- Every release builds, smoke-tests, guards (size, non-root, no setuid, no fixable HIGH/CRITICAL OS advisory), signs (keyless cosign), attests (SLSA provenance, SPDX SBOM) and publishes `ghcr.io/openctemio/openctem-console` for amd64 and arm64, like every other image.
- The all-in-one image (`ghcr.io/openctemio/openctem`) starts the console on loopback port 3001 with the API's console listener on 127.0.0.1:8081, and its gateway serves the console's site on port 8443 (`OPENCTEM_ADMIN_SITE=port`, private client networks only; `off` runs no console). With `GATEWAY=off` the console listens on port 3001 for your own proxy.
- **Upgrade note (all-in-one):** publish port 8443 to reach the console (`-p 8443:8443`), or set `OPENCTEM_ADMIN_SITE=host` with `OPENCTEM_ADMIN_HOST`. The main site no longer serves the console.
