#!/usr/bin/env bash
# Unit test for child-env.sh: bash deploy/allinone/child-env.test.sh
# Each all-in-one process gets only its own environment: no database
# password, encryption key or schema-owner credential reaches web, console or
# gateway, and the schema owner reaches no child at all.
set -u
dir=$(cd "$(dirname "$0")" && pwd)
. "$dir/child-env.sh"
fail=0
export DB_PASSWORD=app-secret DB_ADMIN_PASSWORD=console-secret DB_MIGRATE_USER=owner DB_MIGRATE_PASSWORD=owner-secret \
  DATABASE_URL=postgres://u:app-secret@db/x DATABASE_MIGRATE_URL=postgres://owner:owner-secret@db/x PGPASSWORD=owner-secret \
  APP_ENCRYPTION_KEY=k FINGERPRINT_KEY=f REDIS_PASSWORD=r AUTH_JWT_SECRET=j METRICS_TOKEN=m SMTP_PASSWORD=s \
  BOOTSTRAP_SMTP_PASSWORD=b HTTPS_PROXY=http://user:pw@proxy:3128 \
  NODE_ENV=production NEXT_PUBLIC_APP_URL=https://x BACKEND_API_URL=http://127.0.0.1:8080 ADMIN_API_URL=http://127.0.0.1:8081 \
  LEGAL_PAGES_ENABLED=true OPENCTEM_HOSTNAME=x OPENCTEM_CADDY_ADMIN=unix//tmp/a.sock ACME_EMAIL=a@example.com \
  TLS_CERT_FILE=tls.crt XDG_DATA_HOME=/data/gateway SERVER_PORT=8080 TZ=UTC
envof() { (child_env_scrub "$1"; env); }
has() { # has <role> <name> <want yes|no>
  if envof "$1" | grep -q "^$2="; then got=yes; else got=no; fi
  if [ "$got" != "$3" ]; then echo "FAIL $1 sees $2: $got, want $3" >&2; fail=1; else echo "ok   $1 sees $2: $got"; fi
}
for role in web console gateway; do
  for v in DB_PASSWORD DB_ADMIN_PASSWORD DB_MIGRATE_USER DB_MIGRATE_PASSWORD DATABASE_URL DATABASE_MIGRATE_URL PGPASSWORD \
    APP_ENCRYPTION_KEY FINGERPRINT_KEY REDIS_PASSWORD AUTH_JWT_SECRET METRICS_TOKEN SMTP_PASSWORD BOOTSTRAP_SMTP_PASSWORD SERVER_PORT; do
    has "$role" "$v" no
  done
  has "$role" TZ yes
done
# No secret value at all leaks through a name we did not think of.
for role in web console gateway; do
  if envof "$role" | grep -qE 'secret|=k$|=f$|=r$|=j$|=m$|=s$|=b$'; then echo "FAIL $role sees a secret value" >&2; fail=1; else echo "ok   $role sees no secret value"; fi
done
for v in DB_MIGRATE_USER DB_MIGRATE_PASSWORD DATABASE_MIGRATE_URL PGPASSWORD; do has api "$v" no; done
for v in DB_PASSWORD APP_ENCRYPTION_KEY FINGERPRINT_KEY REDIS_PASSWORD SERVER_PORT; do has api "$v" yes; done
has web NEXT_PUBLIC_APP_URL yes; has web BACKEND_API_URL yes; has web LEGAL_PAGES_ENABLED yes; has web ADMIN_API_URL no
has web HTTPS_PROXY no; has web OPENCTEM_HOSTNAME no
has console ADMIN_API_URL yes; has console NEXT_PUBLIC_APP_URL yes; has console LEGAL_PAGES_ENABLED no
has gateway OPENCTEM_HOSTNAME yes; has gateway OPENCTEM_CADDY_ADMIN yes; has gateway ACME_EMAIL yes; has gateway TLS_CERT_FILE yes
SIGNER_KEY_FILE=/data/signer/keys/signer.pem; export SIGNER_KEY_FILE
has signer SIGNER_KEY_FILE yes; has signer DB_PASSWORD no; has signer APP_ENCRYPTION_KEY no; has signer AUTH_JWT_SECRET no; has api SIGNER_KEY_FILE yes
has gateway SIGNER_KEY_FILE no; has web SIGNER_KEY_FILE no
has gateway XDG_DATA_HOME yes; has gateway HTTPS_PROXY yes; has gateway NODE_ENV no; has gateway BACKEND_API_URL no
[ "$fail" = 0 ] && echo "child-env: OK"
exit "$fail"
