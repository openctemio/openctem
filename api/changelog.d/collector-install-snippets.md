### Fixed: a collector's install commands run the asset collector

- The install commands of a sensor of type Collector rendered the scanner image with a local policy. They now run the asset collector (`SENSOR_COLLECTOR_IMAGE`, default `ghcr.io/openctemio/asset-collector:latest` until the collector tags a release) with its own settings: `SENSOR_API_URL`, the API key and vendor passwords as files (`SENSOR_API_KEY_FILE`, `*_FILE`), one data volume at `/var/lib/openctem`, a `doctor` check before `-daemon`. docker run, Compose and Kubernetes are covered; Helm says the chart bundles the scanner only.
- The docker run snippet's comment now describes the one data volume it mounts (`state/`, `outbox/`, `content/`), not three volumes.
