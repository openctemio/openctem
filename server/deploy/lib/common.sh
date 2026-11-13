# shellcheck shell=bash
# Shared helpers of the Compose operator scripts in server/deploy (install.sh,
# setup.sh): messages, .env read as data and edited with a backup, setting
# validation, the compose file set, the running-stack guards and the image
# signature check. Sourced, never run. Callers set `oc_prog` (message prefix)
# and `here` (the deploy directory) first.

oc_prog="${oc_prog:-openctem}"

say() { printf '%s\n' "$*"; }
info() { printf '%s: %s\n' "$oc_prog" "$*"; }
warn() { printf '%s: WARNING: %s\n' "$oc_prog" "$*" >&2; }
die() {
	printf '%s: %s\n' "$oc_prog" "$*" >&2
	exit 1
}

# The cosign image the signature checks run in, pinned by digest: the trust
# anchor of the check is this digest, so nothing has to be installed on the
# host. No volume and no Docker socket are mounted into it.
OC_COSIGN_IMAGE="${OPENCTEM_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}"
OC_OIDC_ISSUER="https://token.actions.githubusercontent.com"
# Release images: the identity is the publishing workflow at the image's tag.
OC_RELEASE_REPO="ghcr.io/openctemio/"

# ---------------------------------------------------------------------------
# .env as data: never sourced, never executed
# ---------------------------------------------------------------------------

# env_get <file> <NAME>: the value of the last uncommented NAME= line, with a
# trailing " # comment" and surrounding quotes removed. Empty when absent.
env_get() {
	local file="$1" name="$2" line value=""
	[[ -f "$file" ]] || return 0
	while IFS= read -r line || [[ -n "$line" ]]; do
		[[ "$line" == "$name="* ]] || continue
		value="${line#"$name"=}"
	done <"$file"
	value="$(printf '%s' "$value" | sed -E 's/[[:space:]]+#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
	if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
		value="${BASH_REMATCH[1]}"
	fi
	printf '%s' "$value"
}

# env_has <file> <NAME>: true when an uncommented NAME= line exists.
env_has() { [[ -f "$1" ]] && grep -qE "^$2=" "$1"; }

# env_put <file> <NAME> <value>: replace every uncommented NAME= line (the
# first keeps its place, later ones are dropped) or append one. Pure bash, so
# no character of the value is interpreted. The value must be valid
# (valid_setting); the file keeps its mode.
env_put() {
	local file="$1" name="$2" value="$3" line done="" tmp
	tmp="$(mktemp "$file.XXXXXX")"
	chmod 600 "$tmp"
	while IFS= read -r line || [[ -n "$line" ]]; do
		if [[ "$line" == "$name="* ]]; then
			[[ -n "$done" ]] && continue
			printf '%s=%s\n' "$name" "$value" >>"$tmp"
			done=1
		else
			printf '%s\n' "$line" >>"$tmp"
		fi
	done <"$file"
	[[ -n "$done" ]] || printf '%s=%s\n' "$name" "$value" >>"$tmp"
	chmod --reference="$file" "$tmp" 2>/dev/null || true
	mv "$tmp" "$file"
}

# env_backup <file>: one copy per run, mode 0600, named after the time.
# Prints the backup's path.
oc_env_backup=""
env_backup() {
	if [[ -z "$oc_env_backup" ]]; then
		oc_env_backup="$1.bak-$(date -u +%Y%m%dT%H%M%SZ)"
		(umask 077 && cp "$1" "$oc_env_backup")
	fi
	printf '%s' "$oc_env_backup"
}

# env_set <file> <NAME> <value>: change one setting of an existing .env,
# backing the file up first and printing the change (names only for secrets).
env_set() {
	local file="$1" name="$2" value="$3" old backup
	old="$(env_get "$file" "$name")"
	[[ "$old" == "$value" ]] && env_has "$file" "$name" && return 0
	valid_setting "$name" "$value" || die "$name: $oc_reason"
	backup="$(env_backup "$file")"
	env_put "$file" "$name" "$value"
	if is_secret_name "$name"; then
		info "changed $name in $file (value not shown; backup: $backup)"
	elif [[ -z "$old" ]]; then
		info "added $name=$value to $file (backup: $backup)"
	else
		info "changed $name from $old to $value in $file (backup: $backup)"
	fi
}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

is_secret_name() { [[ "$1" =~ (PASSWORD|_KEY|TOKEN|SECRET)$ || "$1" =~ _KEY_ ]]; }

# valid_setting <NAME> <value>: true when the pair is safe to write to .env.
# On false, oc_reason says why without repeating the value (it may be a
# secret). Refused everywhere: a newline, `$` (Compose interpolation), quotes,
# a backslash, a backtick and " #" (a comment to Compose). Secrets take only
# characters that are safe in a connection URL and in Compose, with a minimum
# length, so a typed value fails here and not at the first connection.
oc_reason=""
valid_setting() {
	local name="$1" value="$2"
	oc_reason=""
	[[ "$name" =~ ^[A-Z][A-Z0-9_]*$ ]] || { oc_reason="not a setting name (A-Z, 0-9, _)"; return 1; }
	case "$value" in
	*$'\n'* | *$'\r'* | *'$'* | *'"'* | *"'"* | *$'\\'* | *'`'* | *' #'*)
		oc_reason="the value holds a character .env cannot carry safely (newline, \$, quotes, backslash, backtick or ' #')"
		return 1
		;;
	esac
	case "$name" in
	APP_ENCRYPTION_KEY | FINGERPRINT_KEY | APP_ENCRYPTION_KEY_PREVIOUS)
		[[ "$value" =~ ^[0-9a-f]{64}$ ]] || { oc_reason="must be 64 lowercase hex characters (openssl rand -hex 32)"; return 1; } ;;
	SENSOR_INSTANCE_ENROLLMENT_TOKEN)
		[[ "$value" =~ ^octe_[A-Za-z0-9]{49}$ ]] || { oc_reason="must be octe_ and 49 letters or digits"; return 1; } ;;
	COMPOSE_FILE)
		valid_compose_file "$value" || return 1 ;;
	COMPOSE_PROJECT_NAME)
		[[ "$value" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { oc_reason="must be lowercase letters, digits, - and _"; return 1; } ;;
	*)
		if is_secret_name "$name"; then
			local min=24
			[[ "$name" == REDIS_PASSWORD ]] && min=32
			[[ "$name" == AUTH_JWT_SECRET ]] && min=64
			[[ "$value" =~ ^[A-Za-z0-9._~-]+$ ]] || { oc_reason="a secret may hold only letters, digits and . _ ~ - (safe in a connection URL); generate one with openssl rand -hex 24"; return 1; }
			((${#value} >= min)) || { oc_reason="a secret needs at least $min characters (openssl rand -hex 24)"; return 1; }
		fi
		;;
	esac
	return 0
}

# valid_compose_file <list>: colon-separated docker-compose*.yml names of this
# directory, docker-compose.yml first.
valid_compose_file() {
	local f first=1
	local -a files
	IFS=: read -r -a files <<<"$1"
	((${#files[@]} > 0)) || { oc_reason="empty file list"; return 1; }
	for f in "${files[@]}"; do
		[[ "$f" =~ ^docker-compose[A-Za-z0-9.-]*\.yml$ ]] || { oc_reason="'$f' is not a docker-compose*.yml file name of this directory"; return 1; }
		[[ -f "${here:-.}/$f" ]] || { oc_reason="'$f' does not exist in ${here:-.}"; return 1; }
		if [[ -n "$first" ]]; then
			[[ "$f" == docker-compose.yml ]] || { oc_reason="docker-compose.yml must come first"; return 1; }
			first=""
		fi
	done
	return 0
}

valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }
valid_email() { [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
is_ipv4() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }

# version_ge <a> <b>: true when dotted version a >= b (leading v and any
# suffix after the numbers ignored).
version_ge() {
	local a="${1#v}" b="${2#v}" i
	local -a x y
	IFS=. read -r -a x <<<"${a%%[!0-9.]*}"
	IFS=. read -r -a y <<<"${b%%[!0-9.]*}"
	for i in 0 1 2; do
		((10#${x[i]:-0} > 10#${y[i]:-0})) && return 0
		((10#${x[i]:-0} < 10#${y[i]:-0})) && return 1
	done
	return 0
}

# ---------------------------------------------------------------------------
# The compose file set and the running stack
# ---------------------------------------------------------------------------

# The compose project of this directory: COMPOSE_PROJECT_NAME from .env,
# else the name in docker-compose.yml.
compose_project() {
	local p
	p="$(env_get "$here/.env" COMPOSE_PROJECT_NAME)"
	[[ -n "$p" ]] || p="$(sed -n 's/^name:[[:space:]]*//p' "$here/docker-compose.yml" | head -n 1)"
	printf '%s' "${p:-openctem}"
}

# running_stack_files <project>: the compose files (base names, one per line)
# the project's containers were created with. Empty when nothing runs.
running_stack_files() {
	docker ps -a --filter "label=com.docker.compose.project=$1" \
		--format '{{.Label "com.docker.compose.project.config_files"}}' 2>/dev/null |
		tr ',' '\n' | sed 's|.*/||' | sed '/^$/d' | sort -u
}

# running_stack_dirs <project>: the working directories of its containers.
running_stack_dirs() {
	docker ps -a --filter "label=com.docker.compose.project=$1" \
		--format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | sed '/^$/d' | sort -u
}

# guard_running_stack <project> <wanted COMPOSE_FILE> [droppable file]: stop,
# naming the exact line to add to .env, when a stack of this project name
# already exists in another directory, or was started with a compose file the
# wanted set lacks (an `up` would silently drop that overlay), unless that
# file is the one the operator asked to drop.
guard_running_stack() {
	local project="$1" wanted="$2" droppable="${3:-}" d f missing="" union
	while IFS= read -r d; do
		[[ -z "$d" || "$d" == "$here" ]] && continue
		die "a Compose project named '$project' already exists, started from $d.
  This directory would take over its containers. Give this install its own name:
    COMPOSE_PROJECT_NAME=openctem-2
  in $here/.env, or --set COMPOSE_PROJECT_NAME=openctem-2 when it has no .env yet
  (or run ./install.sh in $d instead)."
	done < <(running_stack_dirs "$project")
	union="$wanted"
	while IFS= read -r f; do
		[[ -z "$f" ]] && continue
		case ":$wanted:" in *":$f:"*) continue ;; esac
		[[ -n "$droppable" && "$f" == "$droppable" ]] && continue
		missing="$missing $f"
		union="$union:$f"
	done < <(running_stack_files "$project")
	[[ -z "$missing" ]] && return 0
	die "the running stack '$project' was started with${missing}, which this run would leave out.
  Keep it: set this line in $here/.env, then run again:
    COMPOSE_FILE=$union"
}

# ---------------------------------------------------------------------------
# Image signatures
# ---------------------------------------------------------------------------

# signing_identity <image ref with tag>: the keyless identity a release image
# is signed with. Empty for images the project does not sign.
signing_identity() {
	local ref="$1" repo tag
	repo="${ref%:*}" tag="${ref##*:}"
	[[ "$ref" == "$OC_RELEASE_REPO"* && "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || return 0
	case "$repo" in
	"${OC_RELEASE_REPO}sensor") printf 'https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/%s' "$tag" ;;
	*) printf 'https://github.com/openctemio/openctem/.github/workflows/docker-publish.yml@refs/tags/%s' "$tag" ;;
	esac
}

# cosign_verify <ref> <identity>: verify keyless in the pinned cosign
# container; print the one manifest digest the signature covers.
cosign_verify() {
	local out digests
	out="$(docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
		--tmpfs /tmp:size=64m -e HOME=/tmp "$OC_COSIGN_IMAGE" \
		verify "$1" --certificate-identity "$2" --certificate-oidc-issuer "$OC_OIDC_ISSUER" \
		--output json 2>/dev/null)" || return 1
	digests="$(printf '%s' "$out" | grep -oE '"docker-manifest-digest":"sha256:[0-9a-f]{64}"' |
		sed -E 's/.*"(sha256:[0-9a-f]{64})"/\1/' | sort -u)"
	[[ -n "$digests" && "$(printf '%s\n' "$digests" | wc -l)" -eq 1 ]] || return 1
	printf '%s' "$digests"
}

# image_has_digest <ref> <sha256:...>: the local image (as pulled) is that digest.
image_has_digest() {
	docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" 2>/dev/null |
		grep -qx "${1%:*}@$2"
}
