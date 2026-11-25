### Added: an optional feed relay sensor for the compose install

- `deploy/docker-compose.relay-sensor.yml` runs a separate container whose only job is to relay the signed feeds
  (relay mode, the platform makes no outbound feed request). It uses the sensor's `-relay` profile image (no tools;
  it reports `feed.relay@1` only, so no scan is ever placed on it), enrolls with its own single-use token
  (`SENSOR_RELAY_ENROLLMENT_TOKEN`, written by `setup.sh`; an older `.env` needs the line from `.env.example`) and
  runs with 256 MiB and half a CPU. Add it to `COMPOSE_FILE`, alone or next to the bundled scanning sensor; designate
  the second one under Console > System > Feed delivery for redundancy. Needs a sensor release that publishes the
  `-relay` image (sensor v0.42.0 or later); its tag follows `sensor.latest` like the bundled sensor's.
- `install.sh` verifies a sensor profile image (`<version>-relay` and the like) against the sensor release
  workflow at its release tag.
- The bundled sensor's default (`sensor.latest`) moves to v0.42.0, the first sensor release that publishes the
  `-relay` image. It scans each target host under a per-host budget, at the Standard pacing level by default; its
  seccomp profile is unchanged from v0.41.1.
- Docs: server/docs/deployment/docker.md, server/docs/architecture/feed-transfer.md, https://github.com/openctemio/sensor/blob/main/docs/PROFILES.md
