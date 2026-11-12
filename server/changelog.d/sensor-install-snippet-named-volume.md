### Changed: the sensor install commands explain the data volume and link the Run the sensor guide

- The `docker run` and Compose install commands keep the sensor's data in a named volume and now say why: a host directory mounted at `/var/lib/openctem` must be owned by the sensor's user (`sudo chown -R 999:999 <dir>`), or the sensor stops at start. The install dialog shows the same note with a link to the Run the sensor guide (English and Vietnamese).
