#!/usr/bin/env bash
# lib.sh: helpers shared by the release scripts (api/docs/rfcs/RFC-037).
# Source it; it defines functions only.
#
#   semver   rel_is_version, rel_version_gt, rel_latest_tag, rel_next_version
#   manifest rel_yaml_get, rel_yaml_set (versions.yaml: two levels, see its header)

# A release version: vMAJOR.MINOR.PATCH, nothing else. Pre-releases (-rc.N) and
# dev builds are never "the last release".
REL_VERSION_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

rel_is_version() {
  [[ "${1:-}" =~ $REL_VERSION_RE ]]
}

# rel_version_gt A B: true when A > B (both vX.Y.Z).
rel_version_gt() {
  [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$1" ]]
}

# rel_latest_tag [git dir]: the highest vX.Y.Z tag, by version sort over ALL
# tags. Never `git describe`: tags live on main and release branches, so on
# develop describe answers with whatever old tag happens to be an ancestor.
rel_latest_tag() {
  git -C "${1:-.}" tag -l 'v*' | grep -E "$REL_VERSION_RE" | sort -V | tail -n 1 || true
}

# rel_bump_kind: reads commit messages on stdin, each terminated by an ASCII
# record separator (git log --format='%B%x1e'), and prints the strongest change among them:
#   breaking  a "type!:" / "type(scope)!:" subject or a BREAKING CHANGE footer
#   feat      a feat subject
#   patch     anything else (fix, perf, deps, docs, ...)
#   none      no commits
rel_bump_kind() {
  awk -v RS='\036' '
    BEGIN { kind = 0 }
    {
      sub(/^\n+/, "")
      if ($0 == "") next
      n = split($0, lines, "\n")
      subject = lines[1]
      k = 1
      if (subject ~ /^[A-Za-z]+(\([^)]*\))?!:/) k = 3
      else if (subject ~ /^feat(\([^)]*\))?:/) k = 2
      for (i = 2; i <= n && k < 3; i++) if (lines[i] ~ /^BREAKING[ -]CHANGE:/) k = 3
      if (k > kind) kind = k
    }
    END { split("none patch feat breaking", names, " "); print names[kind + 1] }
  '
}

# rel_next_version LAST KIND: the version after LAST for a change of KIND.
# Before 1.0.0 a breaking change bumps the minor (0.x makes no stability
# promise, and a 1.0.0 is a decision, not an accident); from 1.0.0 it bumps
# the major. feat bumps the minor, anything else the patch. KIND none prints
# nothing and fails: there is nothing to release.
rel_next_version() {
  local last="$1" kind="$2" major minor patch
  rel_is_version "$last" || { echo "rel_next_version: not a version: '$last'" >&2; return 2; }
  IFS=. read -r major minor patch <<<"${last#v}"
  case "$kind" in
    breaking)
      if [[ "$major" -eq 0 ]]; then echo "v0.$((minor + 1)).0"; else echo "v$((major + 1)).0.0"; fi ;;
    feat) echo "v${major}.$((minor + 1)).0" ;;
    patch) echo "v${major}.${minor}.$((patch + 1))" ;;
    none) return 3 ;;
    *) echo "rel_next_version: unknown kind '$kind'" >&2; return 2 ;;
  esac
}

# rel_yaml_get FILE SECTION.KEY: the value, unquoted ("" for an empty string).
# Fails when the key is missing, so a typo cannot read as "not set".
rel_yaml_get() {
  local file="$1" section="${2%%.*}" key="${2#*.}"
  awk -v s="$section" -v k="$key" '
    /^[^[:space:]#][^:]*:[[:space:]]*(#.*)?$/ { cur = $0; sub(/:.*/, "", cur); next }
    cur == s && $0 ~ "^[[:space:]]+" k ":" {
      v = $0
      sub("^[[:space:]]+" k ":[[:space:]]*", "", v)
      sub(/[[:space:]]+#.*$/, "", v)
      sub(/[[:space:]]+$/, "", v)
      if (v ~ /^".*"$/) v = substr(v, 2, length(v) - 2)
      print v; found = 1; exit
    }
    END { exit found ? 0 : 1 }
  ' "$file"
}

# rel_yaml_set FILE SECTION.KEY VALUE: rewrite one value in place, keeping the
# comments and layout. An empty VALUE is written as "".
rel_yaml_set() {
  local file="$1" section="${2%%.*}" key="${2#*.}" value="$3" tmp
  [[ -z "$value" ]] && value='""'
  tmp="$(mktemp)"
  if ! awk -v s="$section" -v k="$key" -v val="$value" '
    /^[^[:space:]#][^:]*:[[:space:]]*(#.*)?$/ { cur = $0; sub(/:.*/, "", cur) }
    cur == s && !done && $0 ~ "^[[:space:]]+" k ":" {
      match($0, "^[[:space:]]+" k ":")
      print substr($0, 1, RLENGTH) " " val
      done = 1
      next
    }
    { print }
    END { exit done ? 0 : 1 }
  ' "$file" >"$tmp"; then
    rm -f "$tmp"
    echo "rel_yaml_set: $2 not found in $file" >&2
    return 1
  fi
  cat "$tmp" >"$file"
  rm -f "$tmp"
}
