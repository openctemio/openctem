### Security: the compose bundled sensor no longer shares a network with Postgres and Redis

- `docker-compose.sensor.yml` put the sensor, a scanner that parses hostile responses, on the same network as Postgres and Redis. The sensor now runs on its own `sensor-net` bridge, where only the `api` service is also attached: it reaches the API and the internet for public scans, and cannot resolve or connect to Postgres, Redis, the signer, the gateway or the console. The one-shot `sensor-enrollment` job keeps the datastore network.
- The sensor container has memory, CPU and process limits (`SENSOR_MEMORY_LIMIT` 2g, `SENSOR_CPUS` 2, `SENSOR_PIDS_LIMIT` 512).
- **Upgrade note:** run `docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d` again; the sensor is recreated on the new network and keeps its identity in the `sensor-data` volume.
