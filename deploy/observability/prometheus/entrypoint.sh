#!/bin/sh
# Renders the Prometheus configuration from the environment, then starts
# Prometheus. Prometheus does not expand environment variables in its
# configuration, and the API's metrics token must not be written to a file in
# the repository: it goes to a tmpfs file (0400) the scrape job reads.
#
# OBS_RENDER_ONLY=1 renders to OBS_RENDER_DIR (default /run/obs) and exits:
# used by the config check in CI and the end-to-end test.
set -eu

out="${OBS_RENDER_DIR:-/run/obs}"
mkdir -p "${out}"
umask 077

if [ -z "${METRICS_TOKEN:-}" ]; then
	echo "prometheus: METRICS_TOKEN is empty; the API answers 404 on /metrics without it (the ApiScrapeFailing alert will fire)" >&2
fi
printf '%s' "${METRICS_TOKEN:-unset}" >"${out}/api-metrics-token"

api="${OBS_API_UPSTREAM:-api:8080}"
web="${OBS_WEB_UPSTREAM:-ui:3000}"
public="${OBS_PUBLIC_URL:-https://localhost}"
public_module="${OBS_PUBLIC_PROBE_MODULE:-http_2xx}"
containers="${OBS_CONTAINER_REGEX:-openctemio-.*|openctem-sensor.*}"
rules="${OBS_RULES_DIR:-/etc/prometheus/rules}"

cat >"${out}/prometheus.yml" <<EOF
# Rendered by entrypoint.sh at start: edit entrypoint.sh, not this file.
global:
  scrape_interval: 30s
  scrape_timeout: 10s
  evaluation_interval: 30s

rule_files:
  - '${rules}/*.yml'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

scrape_configs:
  - job_name: openctem-api
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: '${out}/api-metrics-token'
    static_configs:
      - targets: ['${api}']

  - job_name: node
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: cadvisor
    static_configs:
      - targets: ['cadvisor:8080']
    metric_relabel_configs:
      # Keep only the platform's containers: fewer series, and scratch
      # containers of other workloads never alert.
      - source_labels: [name]
        regex: '${containers}'
        action: keep

  - job_name: postgres
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: redis
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: blackbox
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets: ['http://${api}/health']
        labels: {probe: api-health}
      - targets: ['http://${web}/login']
        labels: {probe: web-login}
    relabel_configs: &blackbox_relabel
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox:9115

  - job_name: blackbox-public
    metrics_path: /probe
    params:
      module: ['${public_module}']
    static_configs:
      - targets: ['${public}/login']
        labels: {probe: public-login}
    relabel_configs: *blackbox_relabel

  - job_name: prometheus
    static_configs:
      - targets: ['localhost:9090']

  - job_name: alertmanager
    static_configs:
      - targets: ['alertmanager:9093']
EOF

if [ "${OBS_RENDER_ONLY:-0}" = "1" ]; then
	echo "${out}/prometheus.yml"
	exit 0
fi

exec /bin/prometheus \
	--config.file="${out}/prometheus.yml" \
	--storage.tsdb.path=/prometheus \
	--storage.tsdb.retention.time="${OBS_RETENTION_TIME:-15d}" \
	--storage.tsdb.retention.size="${OBS_RETENTION_SIZE:-2GB}" \
	--web.listen-address=:9090
