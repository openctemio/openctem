#!/usr/bin/env bash
# setup.sh: write .env for a first start of the Compose stack: the host name
# clients use and freshly generated secrets. Nothing else needs editing; every
# other setting has a default, and e-mail, sign-in providers and the like are
# set in the admin console after the first sign-in.
#
#   ./setup.sh ctem.example.com                       # TLS from the gateway's own CA
#   ./setup.sh ctem.example.com --acme you@example.com # Let's Encrypt (public DNS name)
#
# It never overwrites an existing .env and never prints a secret. The file is
# created mode 0600: keep it (and a backup of APP_ENCRYPTION_KEY) safe, the
# stored credentials cannot be decrypted without that key.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
env_file="$here/.env"
example="$here/.env.example"

die() { echo "setup: $*" >&2; exit 1; }

host="" acme_email=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --acme) [[ $# -ge 2 ]] || die "--acme needs an e-mail address"; acme_email="$2"; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [[ -z "$host" ]] || die "one host name only"; host="$1" ;;
  esac
  shift
done

[[ -e "$env_file" ]] && die "$env_file already exists; move it away first (this script never overwrites it)"
[[ -f "$example" ]] || die "missing $example"

if [[ -z "$host" && -t 0 ]]; then
  read -r -p "DNS name or IP address browsers and sensors use: " host
fi
[[ -n "$host" ]] || die "usage: ./setup.sh <host name or IP> [--acme you@example.com]"
# A host name or an IP address only: no scheme, port, path or spaces.
[[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "'$host' is not a host name or IPv4 address (no scheme, port or path)"
if [[ -n "$acme_email" ]]; then
  [[ "$acme_email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "'$acme_email' is not an e-mail address"
fi

secret() { # secret <bytes>: hex from the system CSPRNG
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -tx1 -N "$1" /dev/urandom | tr -d ' \n'
  fi
}

base62() { # base62 <length>: letters and digits from the system CSPRNG
  local out=""
  while (( ${#out} < $1 )); do
    out+="$(head -c 256 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${out:0:$1}"
}

umask 077
tmp="$(mktemp "$here/.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
cp "$example" "$tmp"

set_value() { # set_value <NAME> <value>: replace the NAME= line, comment included
  local name="$1" value="$2"
  grep -qE "^${name}=" "$tmp" || die "$example has no ${name}= line"
  # Values are hex, host names or e-mail addresses: no "|" or "&" to escape.
  sed -i -E "s|^${name}=.*$|${name}=${value}|" "$tmp"
}

set_value OPENCTEM_HOSTNAME "$host"
if [[ -n "$acme_email" ]]; then
  set_value OPENCTEM_TLS_MODE acme
  set_value ACME_EMAIL "$acme_email"
fi
set_value DB_SUPERUSER_PASSWORD "$(secret 24)"
set_value DB_MIGRATE_PASSWORD "$(secret 24)"
set_value DB_PASSWORD "$(secret 24)"
set_value REDIS_PASSWORD "$(secret 24)"
set_value APP_ENCRYPTION_KEY "$(secret 32)"
set_value METRICS_TOKEN "$(secret 32)"
# The bundled shared sensor's single-use enrollment token
# (docker-compose.sensor.yml): octe_ and 49 base62 characters.
set_value SENSOR_INSTANCE_ENROLLMENT_TOKEN "octe_$(base62 49)"

chmod 600 "$tmp"
mv "$tmp" "$env_file"
trap - EXIT

cat <<MSG
Wrote $env_file (mode 0600) for https://$host with generated secrets.
Back up APP_ENCRYPTION_KEY from it now: without that key the stored
credentials cannot be decrypted.

Next:
  docker compose up -d
  docker compose run --rm api -check-config   # optional preflight

Optional bundled shared sensor (enrolls with SENSOR_INSTANCE_ENROLLMENT_TOKEN):
  docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d
MSG
