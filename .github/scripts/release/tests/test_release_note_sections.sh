#!/usr/bin/env bash
# Tests for the release-note operator sections: pr-labels.py (labels from the
# changed files), fragment-labels.py (fragment -> pull request labels) and
# changelog.py --labels (the Upgrade notes block).
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
SCRIPTS="$(cd "$RELEASE_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPTS/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

labels() { python3 "$SCRIPTS/pr-labels.py" --files "$1" | tr '\n' ' ' | sed 's/ $//'; }

# --- pr-labels.py ---------------------------------------------------------
cat >"$tmp/plain.json" <<'EOF'
[{"filename": "api/internal/app/scan/service.go", "status": "modified", "patch": "+x"},
 {"filename": "web/src/a.tsx", "status": "modified", "patch": "+y"}]
EOF
assert_eq "an ordinary change gets no label" "" "$(labels "$tmp/plain.json")"

cat >"$tmp/mig.json" <<'EOF'
[{"filename": "api/migrations/000900_add_col.up.sql", "status": "added",
  "patch": "@@ -0,0 +1,2 @@\n+ALTER TABLE findings ADD COLUMN note text;\n+CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_note ON findings(note);"},
 {"filename": "api/migrations/000900_add_col.down.sql", "status": "added",
  "patch": "@@ -0,0 +1 @@\n+ALTER TABLE findings DROP COLUMN note;"}]
EOF
assert_eq "an additive migration is a migration, not destructive (a down file does not count)" \
  "notes:migration" "$(labels "$tmp/mig.json")"

for stmt in 'ALTER TABLE t DROP COLUMN c;' 'drop table old_things;' 'ALTER TABLE t RENAME COLUMN a TO b;' \
  'ALTER TABLE t RENAME TO u;' 'TRUNCATE TABLE cache;' 'ALTER TABLE t ALTER COLUMN c TYPE bigint;' 'DROP SCHEMA x;'; do
  printf '[{"filename": "api/migrations/000901_x.up.sql", "status": "added", "patch": "@@ -0,0 +1 @@\\n+%s"}]\n' "$stmt" >"$tmp/d.json"
  assert_eq "destructive: $stmt" "notes:destructive-migration notes:migration" "$(labels "$tmp/d.json")"
done

cat >"$tmp/comment.json" <<'EOF'
[{"filename": "api/migrations/000902_x.up.sql", "status": "added",
  "patch": "@@ -0,0 +1,2 @@\n+-- we never DROP COLUMN here\n+ALTER TABLE t ADD COLUMN c int;"}]
EOF
assert_eq "a comment that mentions DROP is not destructive" "notes:migration" "$(labels "$tmp/comment.json")"

cat >"$tmp/removed.json" <<'EOF'
[{"filename": "api/migrations/000903_x.up.sql", "status": "removed", "patch": "@@ -1 +0,0 @@\n-DROP TABLE t;"}]
EOF
assert_eq "a deleted migration is not a destructive change" "notes:migration" "$(labels "$tmp/removed.json")"

cat >"$tmp/ident.json" <<'EOF'
[{"filename": "api/pkg/domain/vulnerability/identity_recipes.go", "status": "modified", "patch": "+x"}]
EOF
assert_eq "identity code" "notes:identity" "$(labels "$tmp/ident.json")"
cat >"$tmp/identtest.json" <<'EOF'
[{"filename": "api/pkg/domain/vulnerability/identity_test.go", "status": "modified", "patch": "+x"},
 {"filename": "api/pkg/domain/vulnerability/fingerprint_strategy_test.go", "status": "modified", "patch": "+x"}]
EOF
assert_eq "identity tests alone are not an identity change" "" "$(labels "$tmp/identtest.json")"
cat >"$tmp/ctis.json" <<'EOF'
[{"filename": "api/go.mod", "status": "modified",
  "patch": "@@ -1,3 +1,3 @@\n-\tgithub.com/openctemio/ctis v1.6.0\n+\tgithub.com/openctemio/ctis v1.6.1"}]
EOF
assert_eq "a CTIS module bump" "notes:identity" "$(labels "$tmp/ctis.json")"
cat >"$tmp/othermod.json" <<'EOF'
[{"filename": "api/go.mod", "status": "modified", "patch": "@@ -1 +1 @@\n-\tgithub.com/lib/pq v1.12.2\n+\tgithub.com/lib/pq v1.12.3"}]
EOF
assert_eq "another module bump is not an identity change" "" "$(labels "$tmp/othermod.json")"

cat >"$tmp/contract.json" <<'EOF'
[{"filename": "api/internal/infra/http/handler/asset_handler.go", "status": "modified", "patch": "+x"},
 {"filename": "api/internal/infra/http/routes/assets.go", "status": "modified", "patch": "+x"}]
EOF
assert_eq "handler and route files" "notes:api-contract" "$(labels "$tmp/contract.json")"
cat >"$tmp/contracttest.json" <<'EOF'
[{"filename": "api/internal/infra/http/handler/asset_handler_test.go", "status": "modified", "patch": "+x"}]
EOF
assert_eq "a handler test is not a contract change" "" "$(labels "$tmp/contracttest.json")"
cat >"$tmp/all.json" <<'EOF'
[{"filename": "api/migrations/000904_x.up.sql", "status": "added", "patch": "@@ -0,0 +1 @@\n+DROP TABLE t;"},
 {"filename": "api/internal/infra/http/handler/h.go", "status": "modified", "patch": "+x"},
 {"filename": "api/pkg/domain/vulnerability/fingerprint_composite.go", "status": "modified", "patch": "+x"}]
EOF
assert_eq "all four" "notes:api-contract notes:destructive-migration notes:identity notes:migration" "$(labels "$tmp/all.json")"

# --- fragment-labels.py ---------------------------------------------------
w="$tmp/repo"
new_repo "$w"
mkdir -p "$w/api/changelog.d" "$w/api/scripts" "$tmp/bin"
printf '### Added: widgets\n\n- adds widgets\n' >"$w/api/changelog.d/widgets.md"
git -C "$w" add -A && git -C "$w" commit -q -m "add widgets"
sha_widgets="$(git -C "$w" rev-parse HEAD)"
printf '### Changed: drop the old table\n\n- drops it\n\n### Fixed: a bug\n\n- fixes it\n' >"$w/api/changelog.d/drop-old.md"
git -C "$w" add -A && git -C "$w" commit -q -m "drop old"
sha_drop="$(git -C "$w" rev-parse HEAD)"
printf '### Fixed: orphan\n\n- no pull request\n' >"$w/api/changelog.d/orphan.md"
git -C "$w" add -A && git -C "$w" commit -q -m "orphan"
printf '# readme\n' >"$w/api/changelog.d/README.md"
git -C "$w" add -A && git -C "$w" commit -q -m "readme"

# A stand-in for `gh`: answers the commit -> pull requests call from a table.
cat >"$tmp/bin/gh" <<EOF
#!/usr/bin/env bash
case "\$2" in
  *"/commits/$sha_widgets/pulls") echo '[{"number": 1, "labels": [{"name": "dependencies"}]}]' ;;
  *"/commits/$sha_drop/pulls") echo '[{"number": 2, "labels": [{"name": "notes:destructive-migration"}, {"name": "notes:migration"}, {"name": "security-sensitive"}]}]' ;;
  *) echo '[]' ;;
esac
EOF
chmod +x "$tmp/bin/gh"
PATH="$tmp/bin:$PATH" python3 "$RELEASE_DIR/fragment-labels.py" --repo-dir "$w" --github-repo o/r --out "$tmp/labels.json" 2>"$tmp/err"
assert_eq "only notes: labels are kept, and only for fragments that have some" \
  '{"drop-old.md": ["notes:destructive-migration", "notes:migration"]}' \
  "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$tmp/labels.json")"
assert_contains "a fragment with no pull request is reported" "orphan.md: no pull request" "$(cat "$tmp/err")"
assert_contains "the summary counts it" "1 without a pull request" "$(cat "$tmp/err")"

# --- changelog.py --labels ------------------------------------------------
cp "$REPO_ROOT/api/scripts/changelog.py" "$w/api/scripts/changelog.py"
printf '# Changelog\n\n## Unreleased\n\n## v0.1.0 (2026-01-01)\n\n- old\n' >"$w/api/CHANGELOG.md"
plain="$(python3 "$w/api/scripts/changelog.py" preview)"
assert_not_contains "no labels, no Upgrade notes block" "Upgrade notes" "$plain"
withl="$(python3 "$w/api/scripts/changelog.py" preview --labels "$tmp/labels.json")"
assert_contains "the block is there" "### Upgrade notes" "$withl"
assert_contains "destructive heading" "#### Destructive migrations (read before upgrading)" "$withl"
assert_contains "migration heading" "#### Database migrations" "$withl"
assert_contains "every section title of the fragment is listed" "- Changed: drop the old table (\`drop-old.md\`)" "$withl"
assert_contains "the second section too" "- Fixed: a bug (\`drop-old.md\`)" "$withl"
assert_not_contains "an unlabelled fragment is not listed under a heading" "- Added: widgets (\`widgets.md\`)" "$withl"
assert_contains "the categories still follow" "### Added: widgets" "$withl"
assert_eq "the block comes first" "### Upgrade notes" "$(printf '%s\n' "$withl" | sed -n '3p')"
python3 "$w/api/scripts/changelog.py" release v0.2.0 --labels "$tmp/labels.json" >/dev/null
assert_contains "the release keeps the block" "### Upgrade notes" "$(cat "$w/api/CHANGELOG.md")"
assert_contains "and the old section" "## v0.1.0 (2026-01-01)" "$(cat "$w/api/CHANGELOG.md")"
assert_rc "an unreadable labels file fails" 1 python3 "$w/api/scripts/changelog.py" preview --labels "$tmp/missing.json"

finish
