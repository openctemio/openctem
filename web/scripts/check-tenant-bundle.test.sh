#!/bin/sh
# sh web/scripts/check-tenant-bundle.test.sh
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
fail=0
mkdir -p "$t/clean/app/assets" "$t/route/app/(console)/users" "$t/path/chunks"
echo 'fetch("/api/v1/assets")' > "$t/clean/app/assets/page.js"
echo 'x' > "$t/route/app/(console)/users/page.js"
echo 'fetch("/api/v1/admin/auth/validate")' > "$t/path/chunks/1.js"
sh "$here/check-tenant-bundle.sh" "$t/clean" 2>/dev/null || { echo "FAIL clean build rejected"; fail=1; }
sh "$here/check-tenant-bundle.sh" "$t/route" 2>/dev/null && { echo "FAIL console route id accepted"; fail=1; }
sh "$here/check-tenant-bundle.sh" "$t/path" 2>/dev/null && { echo "FAIL api/v1/admin accepted"; fail=1; }
find "$t" -delete
[ $fail = 0 ] && echo "ok"
exit $fail
