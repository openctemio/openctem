#!/bin/sh
# Unit test for console-plan.sh: bash deploy/allinone/console-plan.test.sh
dir=$(cd "$(dirname "$0")" && pwd)
. "$dir/console-plan.sh"
fail=0
check() { # check <want 0|1> <desc> ; env set by caller
  console_enabled; got=$?
  if [ "$got" -ne "$1" ]; then echo "FAIL $2 (rc $got, want $1)" >&2; fail=1; else echo "ok   $2"; fi
}
(unset OPENCTEM_ADMIN_SITE OPENCTEM_CONSOLE_STANDALONE; GATEWAY=on; check 0 "gateway on runs the console")
(unset OPENCTEM_CONSOLE_STANDALONE; GATEWAY=off; OPENCTEM_ADMIN_SITE=port; check 1 "gateway off does not run the console")
(GATEWAY=off; OPENCTEM_ADMIN_SITE=port; OPENCTEM_CONSOLE_STANDALONE=true; check 0 "gateway off runs it only on explicit opt-in")
(GATEWAY=on; OPENCTEM_ADMIN_SITE=off; check 1 "admin site off never runs it")
[ "$(console_host)" = 127.0.0.1 ] || { echo "FAIL console_host" >&2; fail=1; }
eq() { # eq <want> <got> <desc>
  if [ "$1" != "$2" ]; then echo "FAIL $3 (got '$2', want '$1')" >&2; fail=1; else echo "ok   $3"; fi
}
(OPENCTEM_ADMIN_SITE=port; OPENCTEM_HOSTNAME=ctem.example.com; unset OPENCTEM_ADMIN_PORT OPENCTEM_TLS_MODE
 eq "https://ctem.example.com:8443" "$(console_public_url)" "port mode: host name and default port")
(OPENCTEM_ADMIN_SITE=port; OPENCTEM_HOSTNAME=ctem.example.com; OPENCTEM_ADMIN_PORT=9443
 eq "https://ctem.example.com:9443" "$(console_public_url)" "port mode: configured port")
(OPENCTEM_ADMIN_SITE=host; OPENCTEM_ADMIN_HOST=admin.example.com; OPENCTEM_HOSTNAME=ctem.example.com
 eq "https://admin.example.com" "$(console_public_url)" "host mode: the console's own name")
(OPENCTEM_ADMIN_SITE=off; OPENCTEM_HOSTNAME=ctem.example.com
 eq "" "$(console_public_url)" "site off: no origin")
(OPENCTEM_ADMIN_SITE=port; OPENCTEM_HOSTNAME=ctem.example.com; OPENCTEM_TLS_MODE=http
 eq "" "$(console_public_url)" "port mode behind a TLS proxy: origin unknown")
(OPENCTEM_ADMIN_SITE=host; OPENCTEM_ADMIN_HOST=admin.example.com; OPENCTEM_TLS_MODE=http
 eq "https://admin.example.com" "$(console_public_url)" "host mode behind a TLS proxy: browsers see https")
(OPENCTEM_ADMIN_ALLOWED_CIDRS="10.0.0.0/8  192.168.1.0/24 ::1/128"
 eq "10.0.0.0/8,192.168.1.0/24,::1/128" "$(console_allowed_cidrs)" "gateway networks copied, comma separated")
(unset OPENCTEM_ADMIN_ALLOWED_CIDRS
 eq "" "$(console_allowed_cidrs)" "unset: both default to private networks")
exit $fail
