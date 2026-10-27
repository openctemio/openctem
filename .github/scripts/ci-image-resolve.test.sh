#!/usr/bin/env bash
# Tests for ci-image-resolve.sh with stubbed docker and gh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'find "$tmp" -delete' EXIT
mkdir "$tmp/bin"
D=sha256:$(printf 'a%.0s' $(seq 64))
cat > "$tmp/bin/docker" <<STUB
#!/usr/bin/env bash
# docker buildx imagetools inspect <ref> --format ...
case "\$4" in *:missing*) exit 1 ;; esac
# STUB_ONLY_TAG: only this tag exists (others are missing); unset: every tag exists
if [ -n "\${STUB_ONLY_TAG:-}" ]; then case "\$4" in *":\$STUB_ONLY_TAG") ;; *) exit 1 ;; esac; fi
echo "$D"
STUB
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
# the attestation the test wants: STUB_REF = source ref, STUB_REPO = source repo, STUB_FAIL=1 = no attestation
[ "${STUB_FAIL:-0}" = 1 ] && exit 1
printf '[{"verificationResult":{"signature":{"certificate":{"sourceRepositoryRef":"%s","sourceRepositoryURI":"https://github.com/%s"}}}}]\n' "$STUB_REF" "${STUB_REPO:-openctemio/openctem}"
STUB
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" REPO=openctemio/openctem
fail=0
run() { bash "$here/ci-image-resolve.sh" "$@" 2>/dev/null; }
ok()   { local n="$1"; shift; out="$(run "$@")" && [ "$out" = "ghcr.io/openctemio/ci-images/${img:-api}@$D" ] || { echo "FAIL: $n (want a digest ref)"; fail=1; }; }
none() { local n="$1"; shift; if run "$@" >/dev/null; then echo "FAIL: $n (want no match)"; fail=1; fi; }

Q=refs/heads/gh-readonly-queue/develop/pr-1-abc
SHA=$(printf 'b%.0s' $(seq 40))
unset GITHUB_REF GITHUB_SHA STUB_ONLY_TAG
# --- plain key: only develop and main
export STUB_REF=refs/heads/develop;                       ok "develop build" api k1
export STUB_REF=refs/heads/main;                          ok "main build" api k1
export STUB_REF=$Q;                                       none "queue attestation under the plain key" api k1
export GITHUB_REF=$Q GITHUB_SHA=$SHA STUB_REF=$Q STUB_ONLY_TAG=k1; none "queue attestation under the plain key, from a queue run" api k1
unset GITHUB_REF GITHUB_SHA STUB_ONLY_TAG
export STUB_REF=refs/pull/7/merge;                        none "PR build under the plain key" api k1
export STUB_REF=refs/heads/feature-x;                     none "branch build" api k1
export STUB_REF=refs/heads/develop STUB_REPO=evil/openctem; none "other repository" api k1
export STUB_REPO=openctemio/openctem STUB_FAIL=1;         none "no attestation" api k1
unset STUB_FAIL
export STUB_REF=refs/heads/develop;                       none "missing tag" api missing
# --- queue tag q-<sha>-<key>: only the consumer's own queue ref
export STUB_ONLY_TAG=q-$SHA-k1
export GITHUB_REF=$Q GITHUB_SHA=$SHA
export STUB_REF=$Q;                                       ok "own queue ref's tag" api k1
export STUB_REF=refs/heads/gh-readonly-queue/develop/pr-2-def; none "another queue ref's tag" api k1
export STUB_REF=refs/heads/develop;                       none "develop attestation on a queue tag" api k1
export STUB_REF=refs/pull/7/merge;                        none "PR attestation on a queue tag" api k1
export STUB_REF=$Q STUB_REPO=evil/openctem;               none "queue tag from another repository" api k1
export STUB_REPO=openctemio/openctem
# a queue tag is never looked up by a consumer that is not a queue run
export GITHUB_REF=refs/pull/7/merge STUB_REF=$Q;          none "queue tag from a PR consumer" api k1
export GITHUB_REF=refs/heads/develop STUB_REF=$Q;         none "queue tag from a develop consumer" api k1
# and the SHA must be the consumer's own (another commit's q tag does not exist)
export GITHUB_REF=$Q GITHUB_SHA=$(printf 'c%.0s' $(seq 40)) STUB_REF=$Q; none "queue tag of another commit" api k1
unset GITHUB_REF GITHUB_SHA STUB_ONLY_TAG
run api k1 'x;y' >/dev/null 2>&1 && true
# the attestation check refuses self-hosted runners
grep -q -- '--deny-self-hosted-runners' "$here/ci-image-resolve.sh" || { echo "FAIL: --deny-self-hosted-runners missing"; fail=1; }
[ "$fail" = 0 ] && echo "ci-image-resolve: ok"
exit "$fail"
