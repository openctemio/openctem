#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# install.sh: install and start OpenCTEM with Docker Compose in one command,
# from a bare host to a running, healthy stack and the first sign-in.
#
#   ./install.sh                       # asks a few questions, Enter accepts
#   ./install.sh --yes --host ctem.example.com --admin-email admin@example.com \
#     --backup-admin-email breakglass@example.com --credentials-file ./first-admin.txt
#
# What it does, in order (stops at the first problem and says how to fix it):
#   1. Docker Engine and the Compose plugin (offers to install them on Ubuntu)
#   2. the answers: host name, TLS, first administrator, bundled sensor
#   3. host checks: memory, disk, ports, the stack's network, DNS, the clock
#   4. .env through setup.sh (generated secrets, mode 0600); an existing .env
#      is reused and never overwritten
#   5. the image signatures (keyless cosign, in a container pinned by digest)
#   6. pull, configuration check, start, wait until healthy
#   7. the first platform administrator (bootstrap-admin, credentials shown once)
#   8. the bundled sensor's enrollment, and a summary with the URLs
#
# Options (each also as an environment variable, for automation):
#   --host NAME                  DNS name or IP address browsers and sensors
#                                use (OPENCTEM_INSTALL_HOST)
#   --acme EMAIL                 Let's Encrypt certificate for a public DNS
#                                name; default: the gateway's own CA
#                                (OPENCTEM_INSTALL_ACME_EMAIL)
#   --admin-email EMAIL          first platform administrator
#                                (OPENCTEM_INSTALL_ADMIN_EMAIL)
#   --backup-admin-email EMAIL   break-glass administrator, required with
#                                --admin-email (OPENCTEM_INSTALL_BACKUP_ADMIN_EMAIL)
#   --org-name NAME --org-owner-email EMAIL
#                                also create the first organization and its owner
#   --sensor | --no-sensor       bundled shared sensor (OPENCTEM_INSTALL_SENSOR=yes|no;
#                                default yes for a DNS name, no for an IP address)
#   --credentials-file PATH      without a terminal: write the administrators'
#                                one-time credentials to this new file (0600)
#                                (OPENCTEM_INSTALL_CREDENTIALS_FILE)
#   --version vX.Y.Z             the release (default: this bundle's VERSION)
#   --set NAME=VALUE             any other .env setting for a new .env (repeatable)
#   --admin-site, --admin-host, --admin-port, --admin-cidrs, --admin-public
#                                the platform console's site (see setup.sh -h)
#   --timeout SECONDS            readiness deadline (default 900;
#                                OPENCTEM_INSTALL_TIMEOUT)
#   --no-verify                  skip the image signature check (says so loudly)
#   --force                      continue past failed host checks
#   --install-docker             install Docker without asking (Ubuntu)
#   -y, --yes                    no questions: defaults and the answers given;
#                                a missing required answer is an error
#
# Without a terminal on stdin it never asks: give every answer as an option
# or a variable. It never prints a secret; the administrators' one-time
# credentials appear once, on the terminal (or in --credentials-file).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
env_file="$here/.env"
state_file="$here/.install-state"
oc_prog=install
# shellcheck source=lib/common.sh
. "$here/lib/common.sh"

MIN_DOCKER=24.0.0
MIN_COMPOSE=2.24.0
MIN_MEM_MB=3800   # the Evaluation size: 4 GB (docs.openctem.io/install/sizing)
REC_MEM_MB=7600   # the Small size: 8 GB
MIN_DISK_GB=10
REC_DISK_GB=20

host="${OPENCTEM_INSTALL_HOST:-}"
acme="${OPENCTEM_INSTALL_ACME_EMAIL:-}"
admin_email="${OPENCTEM_INSTALL_ADMIN_EMAIL:-}"
backup_email="${OPENCTEM_INSTALL_BACKUP_ADMIN_EMAIL:-}"
org_name="${OPENCTEM_INSTALL_ORG_NAME:-}"
org_owner="${OPENCTEM_INSTALL_ORG_OWNER_EMAIL:-}"
sensor="${OPENCTEM_INSTALL_SENSOR:-}"
cred_file="${OPENCTEM_INSTALL_CREDENTIALS_FILE:-}"
timeout="${OPENCTEM_INSTALL_TIMEOUT:-900}"
version="${OPENCTEM_VERSION:-}"
yes="" force="" no_verify="" install_docker=""
setup_args=() sets=()

need_arg() { [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
	case "$1" in
	--host) need_arg "$@"; host="$2"; shift ;;
	--acme) need_arg "$@"; acme="$2"; shift ;;
	--admin-email) need_arg "$@"; admin_email="$2"; shift ;;
	--backup-admin-email) need_arg "$@"; backup_email="$2"; shift ;;
	--org-name) need_arg "$@"; org_name="$2"; shift ;;
	--org-owner-email) need_arg "$@"; org_owner="$2"; shift ;;
	--sensor) sensor=yes ;;
	--no-sensor) sensor=no ;;
	--credentials-file) need_arg "$@"; cred_file="$2"; shift ;;
	--version) need_arg "$@"; version="$2"; shift ;;
	--set)
		need_arg "$@"
		[[ "$2" == *=* ]] || die "--set needs NAME=VALUE"
		valid_setting "${2%%=*}" "${2#*=}" || die "--set ${2%%=*}: $oc_reason"
		sets+=("$2"); shift ;;
	--admin-site | --admin-host | --admin-port | --admin-cidrs)
		need_arg "$@"; setup_args+=("$1" "$2"); shift ;;
	--admin-public) setup_args+=("$1") ;;
	--timeout) need_arg "$@"; timeout="$2"; shift ;;
	--no-verify) no_verify=1 ;;
	--force) force=1 ;;
	--install-docker) install_docker=1 ;;
	-y | --yes) yes=1 ;;
	-h | --help) sed -n '3,/^set -euo/{/^#/p}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown option $1 (see ./install.sh --help)" ;;
	esac
	shift
done

[[ "$timeout" =~ ^[1-9][0-9]*$ ]] || die "--timeout must be a number of seconds"
case "$sensor" in "" | yes | no) ;; y | Y | true | 1) sensor=yes ;; n | N | false | 0) sensor=no ;; *) die "OPENCTEM_INSTALL_SENSOR must be yes or no" ;; esac
[[ -z "$version" || "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "'$version' is not a release such as v0.23.0"

# Questions only with a person at a terminal, and never with --yes.
interactive=""
[[ -t 0 && -z "$yes" ]] && interactive=1

# ask <prompt> <default>: one line from the terminal; Enter takes the default.
ask() {
	local answer
	read -r -p "$1${2:+ [$2]}: " answer || die "no answer (end of input)"
	printf '%s' "${answer:-$2}"
}

setting() { # setting <NAME> <default>: --set value, else .env value, else default
	local kv
	for kv in ${sets[@]+"${sets[@]}"}; do [[ "${kv%%=*}" == "$1" ]] && { printf '%s' "${kv#*=}"; return; }; done
	local v
	v="$(env_get "$env_file" "$1")"
	printf '%s' "${v:-$2}"
}

# ---------------------------------------------------------------------------
# 1. Docker Engine and the Compose plugin
# ---------------------------------------------------------------------------
offer_docker_install() {
	local id="" codename=""
	if [[ -r /etc/os-release ]]; then
		id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')"
		codename="$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | tr -d '"')"
	fi
	if [[ "$id" != ubuntu ]] || ! command -v apt-get >/dev/null 2>&1; then
		die "Docker Engine $MIN_DOCKER+ with the Compose plugin $MIN_COMPOSE+ is required.
  Install it for your system (https://docs.docker.com/engine/install/), then run ./install.sh again."
	fi
	if [[ -z "$install_docker" ]]; then
		[[ -n "$interactive" ]] || die "Docker is missing. Install it (sudo apt-get install docker.io docker-compose-v2), or pass --install-docker"
		case "$(ask "Docker is missing. Install Ubuntu's docker.io and docker-compose-v2 packages now (needs sudo)? y/N" n)" in
		y | Y | yes) ;;
		*) die "Docker is required: sudo apt-get install docker.io docker-compose-v2, then run ./install.sh again" ;;
		esac
	fi
	local sudo=()
	[[ "$(id -u)" -eq 0 ]] || sudo=(sudo)
	info "installing docker.io and docker-compose-v2 from the Ubuntu ${codename:-} archive"
	"${sudo[@]}" apt-get update -q
	"${sudo[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2
	"${sudo[@]}" systemctl enable --now docker >/dev/null 2>&1 || true
}

check_docker() {
	if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
		offer_docker_install
	fi
	local err server compose
	if ! err="$(docker version --format '{{.Server.Version}}' 2>&1)"; then
		case "$err" in
		*permission\ denied*) die "this user may not use Docker. Run as root, or as a member of the docker group (which is equivalent to root on this host)" ;;
		*) die "the Docker daemon does not answer: $err
  Start it (sudo systemctl start docker) and run ./install.sh again." ;;
		esac
	fi
	server="$err"
	compose="$(docker compose version --short 2>/dev/null || true)"
	version_ge "$server" "$MIN_DOCKER" || die "Docker Engine $server is older than $MIN_DOCKER: upgrade it first"
	if [[ -z "$compose" ]] || ! version_ge "$compose" "$MIN_COMPOSE"; then
		die "the Docker Compose plugin ${compose:-is missing}${compose:+ is older than $MIN_COMPOSE}: install docker-compose-plugin $MIN_COMPOSE or later"
	fi
	info "Docker Engine $server, Compose ${compose#v}"
}

# ---------------------------------------------------------------------------
# 2. The answers
# ---------------------------------------------------------------------------
default_host() {
	local h
	h="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
	if [[ "$h" == *.* ]] && valid_host "$h"; then printf '%s' "$h"; return; fi
	h="$(hostname -I 2>/dev/null | awk '{print $1}')"
	is_ipv4 "$h" && printf '%s' "$h"
}

reuse=""
[[ -e "$env_file" ]] && reuse=1

# The release to install: --version, else the release this directory is. A
# release bundle carries VERSION. A git checkout installs its release tag; a
# checkout that is not at one (develop, a branch) still has the VERSION of the
# last release merged back, so it is never guessed from: --version is needed.
in_checkout() {
	if command -v git >/dev/null 2>&1; then
		git -C "$here" ls-files --error-unmatch install.sh >/dev/null 2>&1
	else
		[[ -e "$here/../../.git" ]]
	fi
}
if [[ -z "$version" && -z "$reuse" ]] && in_checkout; then
	version="$(git -C "$here" describe --tags --exact-match HEAD 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)"
	[[ -n "$version" ]] || die "this git checkout is not at a release tag, so the release to install is unknown
  (its VERSION file names the last release merged back, not this code). Pass --version vX.Y.Z,
  or check out a release tag first (git checkout vX.Y.Z)."
fi

if [[ -n "$reuse" ]]; then
	# The existing .env decides the host, the TLS mode and the release.
	env_host="$(env_get "$env_file" OPENCTEM_HOSTNAME)"
	env_version="$(env_get "$env_file" OPENCTEM_VERSION)"
	[[ -z "$host" || "$host" == "$env_host" ]] || die "$env_file is for $env_host, not $host. It is never overwritten: install $host from another directory, or move the file away"
	[[ -z "$version" || "$version" == "$env_version" ]] || die "$env_file installs $env_version, not $version. Changing the release is an upgrade, not an install: docs.openctem.io/install/docker-compose/#upgrading-to-a-new-release"
	if [[ -f "$here/VERSION" ]]; then
		bundle="$(tr -d '[:space:]' <"$here/VERSION")"
		[[ "$bundle" == "$env_version" ]] || warn "this directory is release $bundle, its .env installs $env_version"
	fi
	# An answer equal to the .env is fine (a rerun with the same command); a
	# different one is an error naming the line, never a silent "ignored".
	differs() { # differs <option> <NAME> <wanted>
		[[ "$(env_get "$env_file" "$2")" == "$3" ]] ||
			die "$1: the existing $env_file has $2=$(env_get "$env_file" "$2"); change that line in the file (it is never overwritten)"
	}
	[[ -z "$acme" ]] || differs --acme ACME_EMAIL "$acme"
	for ((i = 0; i < ${#setup_args[@]}; i++)); do
		case "${setup_args[i]}" in
		--admin-site) differs --admin-site OPENCTEM_ADMIN_SITE "${setup_args[i + 1]}" ;;
		--admin-host) differs --admin-host OPENCTEM_ADMIN_HOST "${setup_args[i + 1]}" ;;
		--admin-port) differs --admin-port OPENCTEM_ADMIN_PORT "${setup_args[i + 1]}" ;;
		--admin-cidrs) differs --admin-cidrs OPENCTEM_ADMIN_ALLOWED_CIDRS "${setup_args[i + 1]}" ;;
		--admin-public) differs --admin-public OPENCTEM_ADMIN_ALLOWED_CIDRS "0.0.0.0/0 ::/0" ;;
		esac
	done
	host="$env_host" version="$env_version"
	for kv in ${sets[@]+"${sets[@]}"}; do
		[[ "$(env_get "$env_file" "${kv%%=*}")" == "${kv#*=}" ]] ||
			die "--set ${kv%%=*}: the existing $env_file has another value; change that line in the file (it is never overwritten)"
	done
fi

# An explicit --sensor/--no-sensor (or OPENCTEM_INSTALL_SENSOR) may change
# a running install; without one, a rerun keeps what the install has.
sensor_explicit="$sensor"
if [[ -n "$reuse" && -z "$sensor" ]]; then
	sensor=no
	existing="$(env_get "$env_file" COMPOSE_FILE)"
	if [[ -n "$existing" ]]; then
		[[ ":$existing:" == *":docker-compose.sensor.yml:"* ]] && sensor=yes
	elif running_stack_files "$(compose_project)" | grep -qx docker-compose.sensor.yml; then
		sensor=yes
	fi
fi

state_done() { [[ -f "$state_file" ]] && grep -qx "$1=done" "$state_file"; }
mark_done() { (umask 077 && printf '%s=done\n' "$1" >>"$state_file"); }

if [[ -n "$interactive" ]]; then
	say "OpenCTEM install: a few questions, Enter accepts the [default]."
	if [[ -z "$host" ]]; then
		d="$(default_host)"
		while :; do
			host="$(ask "DNS name or IP address browsers and sensors will use" "$d")"
			valid_host "$host" && break
			say "  a host name or IPv4 address only (no https://, port or path)"
		done
	fi
	if [[ -z "$reuse" && -z "$acme" ]] && ! is_ipv4 "$host"; then
		while :; do
			acme="$(ask "E-mail for a Let's Encrypt certificate (needs a public DNS name; Enter: the built-in CA)" "")"
			[[ -z "$acme" ]] || valid_email "$acme" && break
			say "  an e-mail address, or Enter"
		done
	fi
	if [[ -z "$admin_email" ]] && ! state_done bootstrap; then
		while :; do
			admin_email="$(ask "E-mail of the first platform administrator" "")"
			valid_email "$admin_email" && break
			say "  an e-mail address"
		done
	fi
	if [[ -n "$admin_email" && -z "$backup_email" ]] && ! state_done bootstrap; then
		while :; do
			backup_email="$(ask "E-mail of a second, break-glass administrator (another person or mailbox)" "")"
			valid_email "$backup_email" && [[ "$backup_email" != "$admin_email" ]] && break
			say "  a different e-mail address"
		done
	fi
	if [[ -z "$sensor" ]]; then
		d=Y
		is_ipv4 "$host" && d=n
		case "$(ask "Run the bundled sensor (a separate container that scans for this install)? Y/n" "$d")" in
		y | Y | yes) sensor=yes ;; *) sensor=no ;;
		esac
	fi
fi

# Required answers, and what the questions would have checked.
[[ -n "$host" ]] || die "the host name is required: --host <DNS name or IP> (or OPENCTEM_INSTALL_HOST)"
valid_host "$host" || die "'$host' is not a host name or IPv4 address (no scheme, port or path)"
[[ -z "$acme" ]] || valid_email "$acme" || die "'$acme' is not an e-mail address (--acme)"
if [[ -n "$admin_email" ]]; then
	valid_email "$admin_email" || die "'$admin_email' is not an e-mail address (--admin-email)"
	[[ -n "$backup_email" ]] || die "--backup-admin-email is required with --admin-email: a second administrator who can sign in if the first one cannot"
	valid_email "$backup_email" || die "'$backup_email' is not an e-mail address (--backup-admin-email)"
	[[ "$backup_email" != "$admin_email" ]] || die "the break-glass administrator needs a different e-mail address"
fi
[[ -z "$org_name$org_owner" || -n "$admin_email" ]] || die "--org-name and --org-owner-email need --admin-email"
[[ -z "$org_name" || -n "$org_owner" ]] || die "--org-name needs --org-owner-email"
[[ -z "$org_owner" ]] || valid_email "$org_owner" || die "'$org_owner' is not an e-mail address (--org-owner-email)"
if [[ -z "$sensor" ]]; then
	sensor=yes
	is_ipv4 "$host" && sensor=no
fi
[[ "$sensor" == no ]] || ! is_ipv4 "$host" ||
	warn "the bundled sensor reaches the platform by its host name; with an IP address it works only when port 443 of $host is reachable from containers"

# The one-time credentials are shown once: on a terminal, or in a new file.
bootstrap_mode=""
if [[ -n "$admin_email" ]] && ! state_done bootstrap; then
	if [[ -n "$cred_file" ]]; then
		[[ ! -e "$cred_file" ]] || die "$cred_file already exists; name a new file for the one-time credentials"
		[[ -d "$(dirname "$cred_file")" ]] || die "the directory of $cred_file does not exist"
		bootstrap_mode="file"
	elif [[ -t 0 && -t 1 ]]; then
		bootstrap_mode=terminal
	else
		die "the first administrator's one-time credentials are printed once, and there is no terminal here.
  Pass --credentials-file <new file> (written mode 0600; read it, then delete it),
  or leave out --admin-email and create the administrator later at a terminal."
	fi
fi

# The compose file set, recorded in .env (COMPOSE_FILE) so every later
# `docker compose` command and upgrade uses the same files.
compose_file="docker-compose.yml"
[[ "$sensor" == yes ]] && compose_file="$compose_file:docker-compose.sensor.yml"
if [[ -n "$reuse" ]]; then
	existing="$(env_get "$env_file" COMPOSE_FILE)"
	if [[ -n "$existing" ]]; then
		# Keep the operator's overlays; add or drop only the sensor overlay.
		IFS=: read -r -a parts <<<"$existing"
		compose_file="docker-compose.yml"
		for f in "${parts[@]}"; do
			[[ "$f" == docker-compose.yml || "$f" == docker-compose.sensor.yml ]] && continue
			compose_file="$compose_file:$f"
		done
		[[ "$sensor" == yes ]] && compose_file="$compose_file:docker-compose.sensor.yml"
	fi
fi
valid_compose_file "$compose_file" || die "COMPOSE_FILE: $oc_reason"

https_port="$(setting GATEWAY_HTTPS_PORT 443)"
bind="$(setting GATEWAY_BIND 0.0.0.0)"
admin_site="$(setting OPENCTEM_ADMIN_SITE port)"
admin_port="$(setting OPENCTEM_ADMIN_PORT 8443)"
for ((i = 0; i < ${#setup_args[@]}; i++)); do
	case "${setup_args[i]}" in
	--admin-port) admin_port="${setup_args[i + 1]}" ;;
	--admin-site) admin_site="${setup_args[i + 1]}" ;;
	--admin-host) [[ "$admin_site" == off ]] || admin_site=host ;;
	esac
done
public_url="$(setting OPENCTEM_PUBLIC_URL "https://$host$([[ "$https_port" == 443 ]] || printf ':%s' "$https_port")")"

if [[ -n "$interactive" ]]; then
	say ""
	say "  Release:   ${version:-the one this directory is (VERSION)}"
	say "  Address:   $public_url ($([[ -n "$acme" ]] && printf "Let's Encrypt" || printf 'TLS from the built-in CA'))"
	[[ -n "$admin_email" ]] && say "  Admins:    $admin_email, break-glass $backup_email"
	say "  Sensor:    $sensor"
	say "  Directory: $here"
	case "$(ask "Install now? Y/n" Y)" in y | Y | yes) ;; *) die "stopped; nothing was changed" ;; esac
fi

check_docker

# ---------------------------------------------------------------------------
# 3. Host checks: everything is listed, then it stops (unless --force)
# ---------------------------------------------------------------------------
project="$(setting COMPOSE_PROJECT_NAME "")"
[[ -n "$project" ]] || project="$(compose_project)"
problems=()
problem() { problems+=("$1"); }

port_in_use() { # port_in_use <port>: something on this host listens on it
	if command -v ss >/dev/null 2>&1; then
		[[ -n "$(ss -Htln "sport = :$1" 2>/dev/null)" ]]
	else
		(exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
	fi
}

host_checks() {
	local mem_kb mem_mb root free_kb free_gb running net prefix
	mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
	mem_mb=$((mem_kb / 1024))
	if ((mem_mb > 0 && mem_mb < MIN_MEM_MB)); then
		problem "memory: ${mem_mb} MB; the minimum is 4 GB (8 GB for regular use)"
	elif ((mem_mb > 0 && mem_mb < REC_MEM_MB)); then
		warn "memory: ${mem_mb} MB is enough to evaluate; 8 GB is the size for regular use"
	fi

	root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
	for d in "${root:-/var/lib/docker}" "$here"; do
		[[ -d "$d" ]] || continue
		free_kb="$(df -Pk "$d" 2>/dev/null | awk 'NR==2 {print $4}')"
		[[ "$free_kb" =~ ^[0-9]+$ ]] || continue
		free_gb=$((free_kb / 1024 / 1024))
		if ((free_gb < MIN_DISK_GB)); then
			problem "disk: ${free_gb} GB free under $d; at least $MIN_DISK_GB GB are needed (the images, the database and its growth)"
		elif ((free_gb < REC_DISK_GB)); then
			warn "disk: ${free_gb} GB free under $d; keep $REC_DISK_GB GB or more free"
		fi
	done

	running="$(docker ps -q --filter "label=com.docker.compose.project=$project" 2>/dev/null | head -n 1)"
	if [[ -z "$running" ]]; then
		port_in_use "$https_port" && problem "port $https_port is in use on this host: free it, or install on another port with --set GATEWAY_HTTPS_PORT=<port> --set OPENCTEM_PUBLIC_URL=https://$host:<port>"
		if [[ "$admin_site" == port ]]; then
			port_in_use "$admin_port" && problem "port $admin_port (the platform console) is in use: pick another with --admin-port <port>"
		fi
		[[ ":$compose_file:" == *":docker-compose.http-redirect.yml:"* ]] && port_in_use 80 && problem "port 80 is in use (docker-compose.http-redirect.yml publishes it)"
		prefix="$(setting OPENCTEM_NET_PREFIX 172.30.80)"
		while IFS=' ' read -r net subnet; do
			[[ "$subnet" == "$prefix.0/24" && "$net" != "${project}_openctem" ]] &&
				problem "the stack's network $prefix.0/24 is already used by the Docker network '$net': choose another with --set OPENCTEM_NET_PREFIX=172.30.<n>"
		done < <(docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null)
	fi
	[[ "$bind" == 0.0.0.0 || "$bind" == 127.0.0.1 ]] || ip -o addr 2>/dev/null | grep -qF " $bind/" ||
		warn "GATEWAY_BIND=$bind is not an address of this host"

	if ! is_ipv4 "$host"; then
		if ! getent hosts "$host" >/dev/null 2>&1; then
			if [[ -n "$acme" ]]; then
				problem "DNS: $host does not resolve; Let's Encrypt needs a public DNS name that points at this host"
			else
				warn "DNS: $host does not resolve here; add it to your DNS (or the clients' hosts files) before browsers and sensors can reach it"
			fi
		fi
	fi

	# Signatures, certificates and sensor jobs all depend on the clock.
	if command -v timedatectl >/dev/null 2>&1 && [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == no ]]; then
		warn "the clock is not synchronised (NTP): sudo timedatectl set-ntp true"
	fi
	if command -v curl >/dev/null 2>&1; then
		local date now remote skew
		date="$(curl -sSI --max-time 10 https://ghcr.io/v2/ 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: //p' | head -n 1 || true)"
		if [[ -n "$date" ]] && remote="$(date -u -d "$date" +%s 2>/dev/null)"; then
			now="$(date -u +%s)"
			skew=$((now > remote ? now - remote : remote - now))
			((skew <= 120)) || problem "the clock is ${skew}s off (compared with ghcr.io): fix it first, signatures and certificates depend on it (sudo timedatectl set-ntp true)"
		fi
	fi

	((${#problems[@]} == 0)) && { info "host checks passed"; return; }
	for p in "${problems[@]}"; do printf '%s: %s\n' "$oc_prog" "$p" >&2; done
	[[ -n "$force" ]] || die "${#problems[@]} host check(s) failed (listed above). Fix them, or run again with --force"
	warn "continuing despite ${#problems[@]} failed host check(s) (--force)"
}
host_checks

# Before anything is written: a stack of this name elsewhere, or an overlay
# the file set would drop, stops here with the line to add. The sensor overlay
# may be dropped only on an explicit --no-sensor.
droppable=""
[[ "$sensor_explicit" == no ]] && droppable=docker-compose.sensor.yml
guard_running_stack "$project" "$compose_file" "$droppable"

# ---------------------------------------------------------------------------
# 4. .env: written once by setup.sh, then reused
# ---------------------------------------------------------------------------
if [[ -z "$reuse" ]]; then
	args=("$host")
	[[ -z "$version" ]] || args+=(--version "$version")
	[[ -z "$acme" ]] || args+=(--acme "$acme")
	args+=(${setup_args[@]+"${setup_args[@]}"} --set "COMPOSE_FILE=$compose_file")
	for kv in ${sets[@]+"${sets[@]}"}; do args+=(--set "$kv"); done
	# setup.sh prints no secret; only its first paragraph matters here.
	out="$(bash "$here/setup.sh" "${args[@]}")" || exit 1
	printf '%s\n' "$out" | sed '/^$/q' | sed '/^$/d'
	version="$(env_get "$env_file" OPENCTEM_VERSION)"
else
	info "reusing $env_file (never overwritten), release $version"
	# Older .env files have no COMPOSE_FILE: add it (backed up, printed).
	env_set "$env_file" COMPOSE_FILE "$compose_file"
	if [[ "$sensor" == yes && ! -e "$here/sensor/sensor-policy.yaml" ]]; then
		install -m 0644 "$here/sensor/sensor-policy.example.yaml" "$here/sensor/sensor-policy.yaml"
	fi
fi

# Every docker compose call below reads this directory's .env (COMPOSE_FILE
# included), whatever the caller's working directory is.
dc() { (cd "$here" && docker compose "$@"); }

# ---------------------------------------------------------------------------
# 5. Image signatures, 6. pull, check, start
# ---------------------------------------------------------------------------
images="$(dc config --images 2>/dev/null | sort -u)" || die "docker compose cannot read the configuration: run 'docker compose config' in $here to see why"
declare -A verified=()
if [[ -n "$no_verify" ]]; then
	warn "SIGNATURE CHECK SKIPPED (--no-verify): the images are NOT verified. To verify them yourself:"
	while IFS= read -r ref; do
		id="$(signing_identity "$ref")"
		[[ -n "$id" ]] && printf '  cosign verify %s --certificate-identity %s --certificate-oidc-issuer %s\n' "$ref" "$id" "$OC_OIDC_ISSUER" >&2
	done <<<"$images"
else
	info "verifying image signatures (cosign in $OC_COSIGN_IMAGE)"
	while IFS= read -r ref; do
		[[ -n "$ref" ]] || continue
		id="$(signing_identity "$ref")"
		if [[ -z "$id" ]]; then
			case "$ref" in
			"$OC_RELEASE_REPO"*) die "$ref is not a release tag (vX.Y.Z), so its signature cannot be checked against a release. Use a release, or --no-verify for a development image" ;;
			*/*) die "$ref is not a release image; its signature cannot be checked with the release identity. Unset its *_IMAGE override in .env, or pass --no-verify" ;;
			*) info "  $ref: third-party image, pulled from its official repository (not signed by this project)"; continue ;;
			esac
		fi
		digest="$(cosign_verify "$ref" "$id")" || die "the signature of $ref does not verify against $id.
  Do not install this image. Check the release, or verify by hand to see why:
    docker run --rm $OC_COSIGN_IMAGE verify $ref --certificate-identity $id --certificate-oidc-issuer $OC_OIDC_ISSUER"
		verified["$ref"]="$digest"
		info "  $ref: signed by ${id#https://github.com/} ($digest)"
	done <<<"$images"
fi

info "pulling the images"
dc pull --quiet || die "pulling the images failed: run 'docker compose pull' in $here to see which one"
for ref in "${!verified[@]}"; do
	image_has_digest "$ref" "${verified[$ref]}" ||
		die "$ref changed between the signature check and the pull (expected ${verified[$ref]}). Run ./install.sh again"
done

# The configuration check runs in a throwaway api container. While the API
# runs, that container cannot get the API's fixed address; the running API
# checked the same configuration when it started, and `up` below recreates
# it only when the configuration changed (it then fails its health check).
if [[ "$(dc ps --format '{{.State}}' api 2>/dev/null)" == running ]]; then
	info "the API is running: its configuration was checked when it started"
else
	info "checking the configuration"
	if ! out="$(dc run --rm --no-deps -T api -check-config 2>&1)"; then
		printf '%s\n' "$out" >&2
		case "$out" in
		*"configuration INVALID"*) die "the API refuses this configuration (above): fix $env_file and run ./install.sh again" ;;
		*) die "the configuration check could not run (above): cd $here && docker compose run --rm --no-deps api -check-config" ;;
		esac
	fi
fi

if [[ "$(dc ps --format '{{.State}}' api 2>/dev/null)" == running ]]; then
	info "bringing the stack up to date (running services are recreated only if their configuration or image changed)"
else
	info "starting the stack (the first start creates the database: a few minutes)"
fi
up_log="$(mktemp)"
trap 'rm -f "$up_log"' EXIT
# shellcheck disable=SC2016 # $1 is expanded by the inner shell
if ! timeout "$timeout" bash -c 'cd "$1" && docker compose up -d --remove-orphans' _ "$here" >"$up_log" 2>&1; then
	tail -n 20 "$up_log" >&2
	failed="$(dc ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' 2>/dev/null | awk '$2 == "exited" && $3 != 0 {print $1; exit}')"
	die "the stack did not start${failed:+: $failed failed}. See why:
    cd $here && docker compose logs --tail=100 ${failed:-api}"
fi

# Wait for the gateway (healthy only once api, web and console are healthy).
deadline=$((SECONDS + timeout))
while :; do
	health="$(dc ps --format '{{.Service}} {{.Health}}' gateway 2>/dev/null | awk '{print $2}')"
	[[ "$health" == healthy ]] && break
	if ((SECONDS >= deadline)); then
		bad="$(dc ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk '$2 != "" && $2 != "healthy" {print $1; exit}')"
		die "not healthy after ${timeout}s. See why:
    cd $here && docker compose ps && docker compose logs --tail=100 ${bad:-gateway}"
	fi
	sleep 5
done
info "the stack is healthy"

# The sign-in page through the gateway, as a browser reaches it.
if command -v curl >/dev/null 2>&1; then
	addr="$bind"
	[[ "$addr" == 0.0.0.0 ]] && addr=127.0.0.1
	code="$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' --resolve "$host:$https_port:$addr" "https://$host:$https_port/login" || true)"
	if [[ "$code" =~ ^[23] ]]; then
		info "the sign-in page answers (HTTP $code)"
	else
		warn "the sign-in page answered HTTP ${code:-nothing} through the gateway: cd $here && docker compose logs --tail=100 gateway web"
	fi
fi

# ---------------------------------------------------------------------------
# 7. The first platform administrator
# ---------------------------------------------------------------------------
bootstrap_cmd=(bootstrap-admin "-email=$admin_email" "-backup-email=$backup_email")
[[ -z "$org_name" ]] || bootstrap_cmd+=("-org-name=$org_name")
[[ -z "$org_owner" ]] || bootstrap_cmd+=("-org-owner-email=$org_owner")
case "$bootstrap_mode" in
terminal)
	say ""
	say "Creating the platform administrators. Their one-time credentials are shown"
	say "once, below, and nowhere else: copy them now."
	dc run --rm "${bootstrap_cmd[@]}" || die "bootstrap-admin failed (above); run it again: cd $here && docker compose run --rm ${bootstrap_cmd[*]}"
	mark_done bootstrap
	;;
file)
	(umask 077 && dc run --rm -T "${bootstrap_cmd[@]}" -print-secrets >"$cred_file") ||
		{ rm -f "$cred_file"; die "bootstrap-admin failed; run again, or by hand: cd $here && docker compose run --rm ${bootstrap_cmd[*]}"; }
	chmod 600 "$cred_file"
	mark_done bootstrap
	info "the administrators' one-time credentials are in $cred_file (mode 0600): read it, then delete it"
	;;
esac

# ---------------------------------------------------------------------------
# 8. The bundled sensor
# ---------------------------------------------------------------------------
sensor_state=""
if [[ "$sensor" == yes ]]; then
	sensor_state="starting"
	for _ in $(seq 1 24); do
		if [[ "$(dc ps --format '{{.State}}' sensor 2>/dev/null)" != running ]]; then
			sensor_state="not running"
		elif dc logs --no-log-prefix sensor 2>/dev/null | grep -q "Enrolled"; then
			sensor_state="enrolled"
			break
		else
			sensor_state="running, not enrolled yet"
		fi
		sleep 5
	done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
admin_url="$(env_get "$env_file" OPENCTEM_ADMIN_PUBLIC_URL)"
say ""
say "OpenCTEM $version is running."
say "  App:       $public_url"
if [[ "$admin_site" != off && -n "$admin_url" ]]; then
	say "  Console:   $admin_url (platform administration; private networks only by default)"
fi
if [[ -z "$acme" && "$(env_get "$env_file" OPENCTEM_TLS_MODE)" != acme ]]; then
	say "  TLS:       the built-in CA; trust $here/ca/openctem-root-ca.crt in browsers to avoid the warning"
fi
case "$bootstrap_mode" in
terminal | file)
	say "First sign-in: open the console and sign in as $admin_email with the one-time"
	if [[ "$bootstrap_mode" == file ]]; then
		say "  credentials in $cred_file, then change the password and enroll an authenticator app."
	else
		say "  credentials shown above, then change the password and enroll an authenticator app."
	fi
	[[ -n "$org_name" ]] || say "  Then create the first organization there (Organizations) and invite its owner."
	;;
*)
	if state_done bootstrap; then
		say "Administrators: created by an earlier run; sign in to the console."
	else
		say "Create the first platform administrator (at a terminal; credentials shown once):"
		say "  cd $here && docker compose run --rm bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com"
	fi
	;;
esac
if [[ "$sensor" == yes ]]; then
	say "Bundled sensor: $sensor_state. It takes jobs once a super administrator turns on shared"
	say "  sensors (Console > System > Platform scanning).$([[ "$sensor_state" == enrolled ]] || printf ' Logs: cd %s && docker compose logs sensor' "$here")"
fi
say "Settings and secrets: $env_file (mode 0600). Back up APP_ENCRYPTION_KEY from it now:"
say "  without it the stored credentials cannot be decrypted."
say "Day 2 (in $here):"
say "  docker compose ps                  status; logs: docker compose logs -f api"
say "  ./backup.sh backup                 encrypted backup (docs: backup-and-restore)"
say "  upgrade                            docs.openctem.io/install/docker-compose/#upgrading-to-a-new-release"
