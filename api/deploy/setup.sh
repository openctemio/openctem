#!/usr/bin/env bash
# setup.sh: write .env for a first start of the Compose stack: the host name
# clients use and freshly generated secrets. Nothing else needs editing; every
# other setting has a default, and e-mail, sign-in providers and the like are
# set in the admin console after the first sign-in.
#
#   ./setup.sh ctem.example.com                       # TLS from the gateway's own CA
#   ./setup.sh ctem.example.com --acme you@example.com # Let's Encrypt (public DNS name)
#   ./setup.sh ctem.example.com --admin-host admin.ctem.example.com
#                                  # the platform console on its own host name
#                                  # (recommended for production)
#
# The platform console (OPENCTEM_ADMIN_* in .env) has its own site:
#   --admin-site port|host|off   port: https://<host>:<port> (default, no DNS
#                                needed); host: its own DNS name (implied by
#                                --admin-host; the strongest isolation from
#                                the main site); off: no console site
#   --admin-host <name>          the console's DNS name (host mode)
#   --admin-port <port>          the console's port (port mode, default 8443)
#   --admin-cidrs "<cidrs>"      client networks that may reach it, space-
#                                separated (default: private networks only)
#   --admin-public               every network (not recommended: keep it on a
#                                VPN or behind your access gateway instead)
#
# It never overwrites an existing .env and never prints a secret. The file is
# created mode 0600: keep it (and a backup of APP_ENCRYPTION_KEY) safe, the
# stored credentials cannot be decrypted without that key.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
env_file="$here/.env"
example="$here/.env.example"

die() { echo "setup: $*" >&2; exit 1; }

host="" acme_email="" admin_site="" admin_host="" admin_port="" admin_cidrs="" admin_public=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --acme) [[ $# -ge 2 ]] || die "--acme needs an e-mail address"; acme_email="$2"; shift ;;
    --admin-site) [[ $# -ge 2 ]] || die "--admin-site needs port, host or off"; admin_site="$2"; shift ;;
    --admin-host) [[ $# -ge 2 ]] || die "--admin-host needs a host name"; admin_host="$2"; shift ;;
    --admin-port) [[ $# -ge 2 ]] || die "--admin-port needs a port number"; admin_port="$2"; shift ;;
    --admin-cidrs) [[ $# -ge 2 ]] || die "--admin-cidrs needs a list of networks"; admin_cidrs="$2"; shift ;;
    --admin-public) admin_public=1 ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
# The console site: host mode when a console host name is given.
[[ -n "$admin_site" ]] || { [[ -n "$admin_host" ]] && admin_site=host; } || admin_site=port
case "$admin_site" in
  port) [[ -z "$admin_host" ]] || die "--admin-host needs --admin-site host" ;;
  host)
    [[ -n "$admin_host" ]] || die "--admin-site host needs --admin-host <the console's DNS name>"
    [[ -z "$admin_port" ]] || die "--admin-port is for --admin-site port"
    ;;
  off) [[ -z "$admin_host$admin_port$admin_cidrs$admin_public" ]] || die "--admin-site off takes no other console option" ;;
  *) die "--admin-site must be port, host or off" ;;
esac
if [[ -n "$admin_host" ]]; then
  [[ "$admin_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "'$admin_host' is not a host name (no scheme, port or path)"
  [[ "$admin_host" != "$host" ]] || die "--admin-host must differ from the main host name"
fi
if [[ -n "$admin_port" ]]; then
  [[ "$admin_port" =~ ^[1-9][0-9]{0,4}$ ]] && (( admin_port >= 1 && admin_port <= 65535 )) || die "'$admin_port' is not a port number"
  [[ "$admin_port" != 443 && "$admin_port" != 80 ]] || die "--admin-port must not be the main site's port"
fi
if [[ -n "$admin_cidrs" ]]; then
  [[ -z "$admin_public" ]] || die "--admin-cidrs and --admin-public are exclusive"
  for c in $admin_cidrs; do
    [[ "$c" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "--admin-cidrs: '$c' is not an IP address or CIDR"
  done
fi
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
set_value OPENCTEM_ADMIN_SITE "$admin_site"
[[ -z "$admin_host" ]] || set_value OPENCTEM_ADMIN_HOST "$admin_host"
[[ -z "$admin_port" ]] || set_value OPENCTEM_ADMIN_PORT "$admin_port"
[[ -z "$admin_public" ]] || admin_cidrs="0.0.0.0/0 ::/0"
# Spaces in the value: replace the whole line (checked above: no "|" or "&").
[[ -z "$admin_cidrs" ]] || sed -i -E "s|^OPENCTEM_ADMIN_ALLOWED_CIDRS=.*$|OPENCTEM_ADMIN_ALLOWED_CIDRS=${admin_cidrs}|" "$tmp"
set_value DB_SUPERUSER_PASSWORD "$(secret 24)"
set_value DB_MIGRATE_PASSWORD "$(secret 24)"
set_value DB_ADMIN_PASSWORD "$(secret 24)"
set_value DB_PASSWORD "$(secret 24)"
set_value REDIS_PASSWORD "$(secret 24)"
set_value APP_ENCRYPTION_KEY "$(secret 32)"
set_value FINGERPRINT_KEY "$(secret 32)"
set_value METRICS_TOKEN "$(secret 32)"

chmod 600 "$tmp"
mv "$tmp" "$env_file"
trap - EXIT

port="${admin_port:-8443}"
console="https://$host:$port/"
[[ -z "$admin_host" ]] || console="https://$admin_host/"
reach="from private networks only (loopback, 10/8, 172.16/12, 192.168/16, IPv6 ULA)"
[[ -z "$admin_cidrs" ]] || reach="from $admin_cidrs"
[[ -z "$admin_public" ]] || reach="from EVERY network (--admin-public)"
if [[ "$admin_site" = off ]]; then
  console_msg="Platform console: off (--admin-site off)."
else
  console_msg="Platform console: $console, $reach.
From outside those networks, use your VPN"
  if [[ "$admin_site" = port ]]; then
    console_msg="$console_msg or an SSH tunnel, e.g.:
  ssh -L $port:127.0.0.1:$port you@$host   then open https://localhost:$port/
For production, give the console its own DNS name (--admin-host): the
browser then isolates it from the main site entirely."
  else
    console_msg="$console_msg."
  fi
fi

cat <<MSG
Wrote $env_file (mode 0600) for https://$host with generated secrets.
Back up APP_ENCRYPTION_KEY from it now: without that key the stored
credentials cannot be decrypted.

$console_msg

Next:
  docker compose up -d
  docker compose run --rm api -check-config   # optional preflight
MSG
