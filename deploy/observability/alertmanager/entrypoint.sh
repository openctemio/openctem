#!/bin/sh
# Renders the Alertmanager configuration from the environment, then starts
# Alertmanager. Alertmanager does not expand environment variables, and the
# Telegram bot token and the Slack webhook URL are secrets: each goes to a
# tmpfs file (0400) the receiver reads (bot_token_file, api_url_file), never
# into the rendered configuration or the repository.
#
# A receiver is configured only when its variables are set:
#   Telegram: ALERT_TELEGRAM_BOT_TOKEN and ALERT_TELEGRAM_CHAT_ID
#   Slack:    ALERT_SLACK_WEBHOOK_URL
# ALERT_TELEGRAM_API_URL overrides the Telegram API base (tests only).
#
# OBS_RENDER_ONLY=1 renders to OBS_RENDER_DIR (default /run/obs) and exits.
set -eu

out="${OBS_RENDER_DIR:-/run/obs}"
tmpl="${OBS_TEMPLATES_DIR:-/etc/alertmanager/templates}"
mkdir -p "${out}"
umask 077

telegram=""
if [ -n "${ALERT_TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${ALERT_TELEGRAM_CHAT_ID:-}" ]; then
	case "${ALERT_TELEGRAM_CHAT_ID}" in
	'' | *[!0-9-]*)
		echo "alertmanager: ALERT_TELEGRAM_CHAT_ID must be a number (a group id is negative)" >&2
		exit 1
		;;
	esac
	printf '%s' "${ALERT_TELEGRAM_BOT_TOKEN}" >"${out}/telegram-bot-token"
	api_line=""
	if [ -n "${ALERT_TELEGRAM_API_URL:-}" ]; then
		api_line="        api_url: '${ALERT_TELEGRAM_API_URL}'"
	fi
	telegram="    telegram_configs:
      - bot_token_file: '${out}/telegram-bot-token'
        chat_id: ${ALERT_TELEGRAM_CHAT_ID}
${api_line}
        parse_mode: HTML
        disable_notifications: false
        send_resolved: true
        message: '{{ template \"openctem.telegram.message\" . }}'"
elif [ -n "${ALERT_TELEGRAM_BOT_TOKEN:-}${ALERT_TELEGRAM_CHAT_ID:-}" ]; then
	echo "alertmanager: set both ALERT_TELEGRAM_BOT_TOKEN and ALERT_TELEGRAM_CHAT_ID (Telegram receiver left out)" >&2
fi

slack=""
if [ -n "${ALERT_SLACK_WEBHOOK_URL:-}" ]; then
	printf '%s' "${ALERT_SLACK_WEBHOOK_URL}" >"${out}/slack-webhook-url"
	slack="    slack_configs:
      - api_url_file: '${out}/slack-webhook-url'
        send_resolved: true
        title: '{{ template \"openctem.slack.title\" . }}'
        text: '{{ template \"openctem.slack.text\" . }}'
        color: '{{ template \"openctem.slack.color\" . }}'"
fi

if [ -z "${telegram}${slack}" ]; then
	echo "alertmanager: no receiver configured (set the Telegram and/or Slack variables); alerts are kept in the Alertmanager UI only" >&2
fi

cat >"${out}/alertmanager.yml" <<EOF
# Rendered by entrypoint.sh at start: edit entrypoint.sh, not this file.
templates:
  - '${tmpl}/*.tmpl'

route:
  receiver: operators
  group_by: [alertname, severity]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    # Unhardened sensors are a standing nudge, not an incident: one
    # notification per kind, repeated once a day.
    - matchers: [alertname="SensorsUnhardened"]
      receiver: operators
      group_by: [alertname, kind]
      repeat_interval: 24h
    - matchers: [severity="critical"]
      receiver: operators
      repeat_interval: 1h
    - matchers: [severity="warning"]
      receiver: operators
      repeat_interval: 12h

inhibit_rules:
  # The critical level of an alert hides its warning level.
  - source_matchers: [severity="critical"]
    target_matchers: [severity="warning"]
    equal: [alertname]
  # The API down (or its database down) explains every alert the API reports.
  - source_matchers: [alertname=~"ApiDown|PostgresDown"]
    target_matchers: [component="api"]

receivers:
  - name: operators
${telegram}
${slack}
EOF

if [ "${OBS_RENDER_ONLY:-0}" = "1" ]; then
	echo "${out}/alertmanager.yml"
	exit 0
fi

exec /bin/alertmanager \
	--config.file="${out}/alertmanager.yml" \
	--storage.path=/alertmanager \
	--web.listen-address=:9093 \
	--web.external-url="${OBS_ALERTMANAGER_URL:-http://127.0.0.1:9093}" \
	--cluster.listen-address=
