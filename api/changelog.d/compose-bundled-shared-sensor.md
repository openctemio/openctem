### Added: compose overlay for a bundled sensor enrolled as a shared sensor

- `api/deploy/docker-compose.sensor.yml` runs a sensor next to the stack that enrolls as a shared sensor of the instance. A one-shot `sensor-enrollment` service registers `SENSOR_INSTANCE_ENROLLMENT_TOKEN` (`bootstrap-admin sensor-token`, valid one hour, single use) after the migrations; the sensor enrolls with it on first start and keeps its identity in the `sensor-data` volume.
- `setup.sh` writes a generated `SENSOR_INSTANCE_ENROLLMENT_TOKEN` (`octe_` and 49 letters or digits) into a new `.env`.
- **Upgrade note:** the overlay is opt-in. An existing install whose sensor was paired as an organization sensor keeps it; add `SENSOR_INSTANCE_ENROLLMENT_TOKEN` to `.env` (octe_ and 49 letters or digits) only to start the overlay.
