# Sourced by openctem-supervise (bash). Each process of the all-in-one image
# gets only the environment it needs, so a bug that exposes one process's
# environment (an error page, a debug endpoint, a code-execution bug in a
# Node dependency) does not hand over the database passwords or the
# encryption key of the others.
#
#   api      everything except the schema owner's credentials (the start-up
#            migrations are the only user of DB_MIGRATE_* / DATABASE_MIGRATE_URL)
#   web      the web console: its own NEXT_* / cookie / legal settings
#   console  the platform console: the same, plus ADMIN_API_URL
#   signer   the job signer: SIGNER_* only (its key and ledger settings)
#   gateway  Caddy and its entrypoint: OPENCTEM_*, TLS, ACME, proxies
#
# A variable that is not listed here does not reach web, console or gateway.
# When one of them needs a new setting, add it to its list below (and to
# child-env.test.sh).

# The schema owner: never passed to any child.
child_env_owner_var() {
  case "$1" in
    DB_MIGRATE_USER | DB_MIGRATE_PASSWORD | DATABASE_MIGRATE_URL | PGPASSWORD | PGPASSFILE) return 0 ;;
  esac
  return 1
}

# Allowed for every child: process basics with no secret in them.
child_env_common_var() {
  case "$1" in
    PATH | HOME | TZ | LANG | LC_* | TERM | SSL_CERT_FILE | SSL_CERT_DIR) return 0 ;;
  esac
  return 1
}

# child_env_keep <role> <name>: 0 when <name> may reach <role>.
child_env_keep() {
  local role="$1" name="$2"
  child_env_owner_var "$name" && return 1
  case "$role" in
    api) return 0 ;;
  esac
  child_env_common_var "$name" && return 0
  case "$role" in
    web | console)
      case "$name" in
        NODE_ENV | NODE_OPTIONS | NODE_EXTRA_CA_CERTS | NEXT_* | PORT | HOSTNAME | \
          BACKEND_API_URL | SECURE_COOKIES | TRUST_PROXY_HEADERS | COOKIE_MAX_AGE) return 0 ;;
      esac
      if [ "$role" = web ]; then
        case "$name" in
          LEGAL_* | SECURITY_CONTACT | SECURITY_POLICY_URL | SECURITY_TXT_ENABLED) return 0 ;;
        esac
      else
        case "$name" in
          ADMIN_API_URL) return 0 ;;
        esac
      fi
      ;;
    signer)
      case "$name" in SIGNER_*) return 0 ;; esac
      ;;
    gateway)
      case "$name" in
        OPENCTEM_* | ACME_* | GATEWAY_* | TLS_CERT_FILE | TLS_KEY_FILE | SENSOR_PUBLIC_HOSTNAME | \
          SENSOR_MTLS_UPSTREAM | XDG_DATA_HOME | XDG_CONFIG_HOME | \
          HTTP_PROXY | HTTPS_PROXY | NO_PROXY | http_proxy | https_proxy | no_proxy) return 0 ;;
      esac
      ;;
  esac
  return 1
}

# child_env_scrub <role>: unsets, in the calling (sub)shell, every exported
# variable <role> must not see. Run it in the subshell that then execs the
# child: the values never go through argv (as `env -i NAME=value` would).
child_env_scrub() {
  local role="$1" name
  for name in $(compgen -e); do
    child_env_keep "$role" "$name" || unset "$name" 2>/dev/null || true
  done
}
