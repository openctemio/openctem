#!/bin/sh
# The tenant app's build output must hold nothing of the platform console: its
# route ids (the (console) route group) and the console's API path
# /api/v1/admin. The console ships only in its own image; a tenant build that
# contains them would serve console pages to tenant users.
# Usage: check-tenant-bundle.sh [dir]   (default .next/server)
dir="${1:-.next/server}"
[ -d "$dir" ] || { echo "check-tenant-bundle: $dir is not a directory" >&2; exit 2; }
bad=0
# Route ids and file names.
if find "$dir" -path '*(console)*' | grep -q .; then
  echo "tenant build contains console route ids:" >&2; find "$dir" -path '*(console)*' | head -5 >&2; bad=1
fi
# Route ids inside manifests (source maps carry source comments, so they are skipped).
if grep -rIlF --exclude='*.map' -e '/(console)/' -e 'app/(console)' "$dir" | head -3 | grep -q .; then
  echo "tenant build manifests name console routes" >&2; bad=1
fi
# The console's API path in any emitted file.
if grep -rIl --exclude='*.map' 'api/v1/admin' "$dir" | head -5 | grep -q .; then
  echo "tenant build references api/v1/admin:" >&2; grep -rIl --exclude='*.map' 'api/v1/admin' "$dir" | head -5 >&2; bad=1
fi
exit $bad
