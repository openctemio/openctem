#!/usr/bin/env bash
# Validates the monitoring stack configuration with the pinned images:
# renders the Prometheus and Alertmanager configurations through their
# entrypoints (with and without receivers), then runs promtool (config, rules,
# rule unit tests) and amtool (config, templates). Needs docker; no network
# beyond pulling the two images. Run from anywhere:
#
#   deploy/observability/test/check-config.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prom_image="$(sed -n 's/^ *image: \(prom\/prometheus:.*\)$/\1/p' "${here}/docker-compose.yml")"
am_image="$(sed -n 's/^ *image: \(prom\/alertmanager:.*\)$/\1/p' "${here}/docker-compose.yml")"

echo "== Prometheus (${prom_image})"
docker run --rm -v "${here}/prometheus:/etc/prometheus:ro" \
	-e OBS_RENDER_ONLY=1 -e OBS_RENDER_DIR=/tmp/obs -e METRICS_TOKEN=check \
	--entrypoint /bin/sh "${prom_image}" -c '
		set -e
		/bin/sh /etc/prometheus/entrypoint.sh >/dev/null
		promtool check config /tmp/obs/prometheus.yml
		cd /etc/prometheus/tests && promtool test rules openctem_test.yml'

check_am() {
	local label="$1"
	shift
	echo "== Alertmanager (${am_image}): ${label}"
	docker run --rm -v "${here}/alertmanager:/etc/alertmanager:ro" \
		-e OBS_RENDER_ONLY=1 -e OBS_RENDER_DIR=/tmp/obs "$@" \
		--entrypoint /bin/sh "${am_image}" -c '
			set -e
			/bin/sh /etc/alertmanager/entrypoint.sh >/dev/null
			amtool check-config /tmp/obs/alertmanager.yml
			if grep -qE "bot_token:|api_url: .https://hooks" /tmp/obs/alertmanager.yml; then
				echo "a secret was written into the rendered configuration" >&2
				exit 1
			fi'
}

check_am "no receiver"
check_am "Telegram and Slack" \
	-e ALERT_TELEGRAM_BOT_TOKEN=123:check -e ALERT_TELEGRAM_CHAT_ID=-1001 \
	-e ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.invalid/services/T/B/X
check_am "Slack only" -e ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.invalid/services/T/B/X

echo "== a non-numeric Telegram chat id is refused"
if docker run --rm -v "${here}/alertmanager:/etc/alertmanager:ro" \
	-e OBS_RENDER_ONLY=1 -e OBS_RENDER_DIR=/tmp/obs \
	-e ALERT_TELEGRAM_BOT_TOKEN=123:check -e "ALERT_TELEGRAM_CHAT_ID=1; rm -rf /" \
	--entrypoint /bin/sh "${am_image}" /etc/alertmanager/entrypoint.sh >/dev/null 2>&1; then
	echo "accepted a non-numeric chat id" >&2
	exit 1
fi

echo "OK"
