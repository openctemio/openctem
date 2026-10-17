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
exit $fail
