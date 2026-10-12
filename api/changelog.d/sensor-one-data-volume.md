### Changed: sensor install snippets mount one data volume

- The docker run, Compose and Kubernetes snippets mount ONE volume at
  `/var/lib/openctem` (the sensor's `state/`, `outbox/` and `content/`)
  instead of three; the Kubernetes manifest has one 8Gi PVC
  (`<sensor>-data`), and the Helm snippet sets
  `sensor.data.persistence.enabled=true` (chart 0.19.0+). Sensors installed
  with three volumes keep working; the sensor README has the migration.
- The setup checklist explains the sensor's new `storage.outbox_persistent`
  check (an outbox off any volume loses undelivered results when the
  container is recreated), and the state and key-renewal fixes point at the
  data volume.
