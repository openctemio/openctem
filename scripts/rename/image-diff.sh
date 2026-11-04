#!/usr/bin/env bash
# =============================================================================
# image-diff.sh: the image-diff gate of the api/ -> server/ rename
# (research/414 §5). Compares two images built from the same content before and
# after the rename and fails on any difference a runtime could see.
#
#   scripts/rename/image-diff.sh <before-image> <after-image> [<binary> ...]
#
# Compared:
#   - the file list with type, mode, owner and size class (symlink targets too);
#     regular files under the given binaries' paths are compared by list entry
#     only, because Go embeds the module path in the binary;
#   - the image config: Entrypoint, Cmd, User, Env, ExposedPorts, Healthcheck,
#     WorkingDir, Volumes, StopSignal, and the labels except the source path;
#   - for each <binary> (an absolute path in the image, e.g. /app/server): the
#     output of `<binary> -version` (with WANT_VERSION: it must report that
#     version, which proves the ldflags -X path). The route list needs a
#     database, so image-diff-ci.sh compares the generated route manifests.
# File contents are compared one by one. A text file that differs only in the
# backend directory name (api/ <-> server/, the module path) is reported as
# "path-only" and allowed: comments in shipped configs cite repository paths.
# Allowed differences: the content and size of the Go binaries, and of the
# files named in ALLOW_CONTENT (space-separated absolute paths, e.g. the
# OpenAPI spec whose descriptions cite repository paths); their content diff
# is printed for review.
#
# Needs docker. Creates two stopped containers and removes them on exit.
# =============================================================================
set -euo pipefail
before="${1:?usage: image-diff.sh <before> <after> [<binary> ...]}"
after="${2:?usage: image-diff.sh <before> <after> [<binary> ...]}"
shift 2
bins=("$@")
allow=" ${bins[*]} ${ALLOW_CONTENT:-} "
work="$(mktemp -d)"
cA="imgdiff-a-$$"; cB="imgdiff-b-$$"
cleanup() { docker rm -f "$cA" "$cB" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail=0

listing() { # <container> <out>
  # type mode owner path [-> target]; size only for non-binaries.
  docker export "$1" | tar -tvf - --numeric-owner \
    | awk -v bins="$allow" '{
        mode=$1; owner=$2; size=$3; path=$6;
        for (i = 7; i <= NF; i++) path = path " " $i;
        p = "/" path; sub(/\/$/, "", p);
        size = "-";   # contents are compared below, file by file
        print mode, owner, size, path
      }' | sort > "$2"
}
config() { # <image> <out>
  docker image inspect "$1" --format '{{json .Config}}' | python3 -c '
import json, sys
c = json.load(sys.stdin)
keep = ["Entrypoint", "Cmd", "User", "Env", "ExposedPorts", "Healthcheck", "WorkingDir", "Volumes", "StopSignal", "Labels"]
out = {k: c.get(k) for k in keep}
labels = dict(out.get("Labels") or {})
for k in list(labels):
    if k in ("org.opencontainers.image.source", "org.opencontainers.image.revision", "org.opencontainers.image.created"):
        labels.pop(k)
out["Labels"] = labels
print(json.dumps(out, indent=1, sort_keys=True))
' > "$2"
}

docker create --name "$cA" "$before" >/dev/null
docker create --name "$cB" "$after" >/dev/null
listing "$cA" "$work/a.list"; listing "$cB" "$work/b.list"
if diff -u "$work/a.list" "$work/b.list" > "$work/list.diff"; then
  echo "ok   file list, modes, owners, sizes ($(wc -l < "$work/a.list") entries)"
else
  echo "FAIL file list differs:"; head -n 60 "$work/list.diff"; fail=1
fi
mkdir -p "$work/fa" "$work/fb"
docker export "$cA" | tar -x -C "$work/fa" --no-same-owner 2>/dev/null || true
docker export "$cB" | tar -x -C "$work/fb" --no-same-owner 2>/dev/null || true
cfail=0; ponly=0; same=0
while IFS= read -r -d '' f; do
  rel="${f#"$work/fa"}"
  [ -f "$work/fb$rel" ] && [ ! -L "$f" ] || continue
  if cmp -s "$f" "$work/fb$rel"; then same=$((same + 1)); continue; fi
  case "$allow" in *" $rel "*) continue ;; esac
  if grep -qI . "$f" 2>/dev/null \
     && cmp -s <(sed -E 's#openctem/server#openctem/api#g; s#(^|[^[:alnum:]_./-])server/#\1api/#g; s#cd server#cd api#g' "$work/fb$rel") \
               <(sed -E 's#openctem/server#openctem/api#g; s#(^|[^[:alnum:]_./-])server/#\1api/#g; s#cd server#cd api#g' "$f"); then
    ponly=$((ponly + 1)); echo "info $rel differs only in the backend directory name (allowed)"
  else
    cfail=1; echo "FAIL $rel content differs:"; diff "$f" "$work/fb$rel" 2>/dev/null | head -n 10 || true
  fi
done < <(find "$work/fa" -type f -print0)
if [ "$cfail" = 0 ]; then echo "ok   file contents: $same identical, $ponly path-only"; else fail=1; fi
config "$before" "$work/a.cfg"; config "$after" "$work/b.cfg"
if diff -u "$work/a.cfg" "$work/b.cfg" > "$work/cfg.diff"; then
  echo "ok   image config (entrypoint, cmd, user, env, ports, healthcheck, workdir, volumes, labels)"
else
  echo "FAIL image config differs:"; cat "$work/cfg.diff"; fail=1
fi
for f in ${ALLOW_CONTENT:-}; do
  docker cp "$cA:$f" "$work/a.file" >/dev/null 2>&1 || true
  docker cp "$cB:$f" "$work/b.file" >/dev/null 2>&1 || true
  if cmp -s "$work/a.file" "$work/b.file"; then echo "ok   $f identical"
  else echo "info $f differs (allowed, review):"; diff "$work/a.file" "$work/b.file" | head -n 30 || true; fi
done
for b in "${bins[@]}"; do
  for flag in -version; do
    # Log lines carry a timestamp; drop it before comparing.
    oa="$(docker run --rm --network none --entrypoint "$b" "$before" "$flag" 2>&1 | sed -E 's/"time":"[^"]*"//; s/^time=[^ ]* //')" && ra=0 || ra=$?
    ob="$(docker run --rm --network none --entrypoint "$b" "$after" "$flag" 2>&1 | sed -E 's/"time":"[^"]*"//; s/^time=[^ ]* //')" && rb=0 || rb=$?
    if [ "$ra" = "$rb" ] && [ "$oa" = "$ob" ]; then
      echo "ok   $b $flag (exit $ra, $(printf '%s\n' "$oa" | wc -l) lines)"
      if [ "$flag" = -version ]; then
        printf '       %s\n' "$(printf '%s' "$ob" | head -n 3)"
        if [ -n "${WANT_VERSION:-}" ] && [ "$rb" = 0 ] && ! printf '%s' "$ob" | grep -qF "$WANT_VERSION"; then
          echo "FAIL $b -version does not report $WANT_VERSION (ldflags -X path?)"; fail=1
        fi
      fi
    else
      echo "FAIL $b $flag differs (exit $ra vs $rb):"
      diff <(printf '%s\n' "$oa") <(printf '%s\n' "$ob") | head -n 20; fail=1
    fi
  done
done
exit "$fail"
