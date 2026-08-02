#!/usr/bin/env bash
#
# Security lint — catches "primitive built, but not mounted" regressions.
#
# The audit kept finding the same class of bug: a defence primitive
# existed in pkg/* but the business code still used a vulnerable
# pattern directly (&http.Client{} outside pkg/httpsec, etc.). Once
# fixed, we do not want someone to reintroduce the bad pattern in a
# follow-up PR without noticing. This script runs in CI and fails the
# build on any regression.
#
# The rules are deliberately conservative: the audit lists every
# allow-listed exception below. If you genuinely need a new
# exception, edit this script in the same PR so the reviewer sees it.
#
# Rules 1, 4 and 6 read sibling repositories (agent/, sdk-go/), so the script
# expects a workspace laid out as <root>/{api,agent,sdk-go}. Point SECLINT_ROOT
# at that workspace when the script is not being run from inside it — CI checks
# the three repositories out side by side and does exactly that.
#
# SECLINT_STRICT=1 turns a missing sibling into a failure instead of a warning.
# CI must set it. Without it a workspace holding only api/ runs 4 of 6 rules,
# prints warnings nobody reads, and exits 0 — a green check that verified two
# thirds of what it claims. That failure mode is the reason this gate spent its
# whole life in a repository that does not exist on GitHub.
#
# Exit codes: 0 pass, 1 at least one rule failed, 2 script-usage bug.

set -u -o pipefail

ROOT="${SECLINT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2

STRICT="${SECLINT_STRICT:-0}"

RED=$'\033[0;31m'
GRN=$'\033[0;32m'
YEL=$'\033[1;33m'
RST=$'\033[0m'

fail=0

say_fail() { printf '%s[FAIL]%s %s\n' "$RED" "$RST" "$*"; fail=1; }
say_pass() { printf '%s[PASS]%s %s\n' "$GRN" "$RST" "$*"; }
say_warn() { printf '%s[WARN]%s %s\n' "$YEL" "$RST" "$*"; }

# A rule that cannot run is not a rule that passed. In strict mode this is
# fatal; locally it stays a warning so the script is still usable from a
# partial checkout.
# Distinct from say_skip. say_skip means "I could not run" — a misconfiguration,
# fatal in strict mode. say_gap means "I ran, and the thing being asserted has
# genuinely not been built yet". A gap is tracked and printed loudly on every
# run, but it does not block, because a permanently-red gate gets switched off
# and then protects nothing.
say_gap() { printf '%s[GAP]%s %s\n' "$YEL" "$RST" "$*"; }

say_skip() {
    if [[ "$STRICT" == "1" ]]; then
        say_fail "$* (SECLINT_STRICT=1: a rule that cannot run counts as failed)"
    else
        say_warn "$*"
    fi
}

# ---------------------------------------------------------------------------
# Rule 1: outbound HTTP clients must use pkg/httpsec.
#
# The "&http.Client{" literal outside pkg/httpsec is the audit's C1/C2
# fingerprint — it means the outbound client bypasses the SSRF dialer
# that rejects loopback / RFC1918 / link-local / CGNAT targets.
#
# Exceptions: test files (fine to construct a naive client for unit
# tests) and pkg/httpsec itself.
# ---------------------------------------------------------------------------
check_http_client() {
    # Scope: api/ and agent/. We do NOT scan sdk-go/ — the SDK is its
    # own Go module and cannot import api/pkg/httpsec without a cross-
    # module dep. Lifting httpsec into a shared module is tracked as a
    # follow-up (see RFC-007 roadmap). For now SDK clients are
    # outbound-to-tenant-configured-URLs only and the dialer hygiene
    # is accepted as risk at that layer.
    #
    # Allow-list: specific file:line sites that legitimately construct
    # &http.Client{...} — each justified in a comment at the site.
    # NEW additions MUST be paired with a comment explaining why httpsec
    # is not applicable; the reviewer checks this list during code review.
    local allow_sites=(
        # pkg/httpsec itself builds the SafeHTTPClient wrapper.
        'api/pkg/httpsec/ssrf.go'
        # Admin CLI talks to its own API over an operator-provided URL
        # (same trust domain as the server). Not tenant-facing.
        'api/cmd/openctem-admin/cmd/client.go'
        # Fetchers already import httpsec and use ValidateURL /
        # IsIPBlocked with a custom dialer. The &http.Client{...} here
        # wraps that custom dialer, equivalent to SafeHTTPClient.
        'api/internal/infra/fetchers/http_fetcher.go'
        # Webhook fallback: SafeHTTPClient is attempted first; the
        # fallback path only fires when the helper returns nil (tests).
        'api/internal/infra/notifier/webhook.go'
        # Workflow HTTPRequestHandler implements its own SSRF guard
        # inline (validateURL + safeDialer + CheckRedirect). Functionally
        # equivalent to SafeHTTPClient; consolidation is a follow-up.
        'api/internal/app/workflow/handlers.go'
    )

    local hits
    hits="$(grep -RnE '&http\.Client\{' \
        --include='*.go' \
        --exclude-dir='pkg/httpsec' \
        --exclude-dir='vendor' \
        --exclude-dir='tmp' \
        --exclude-dir='.claude' \
        --exclude-dir='node_modules' \
        --exclude='*_test.go' \
        api/ agent/ 2>/dev/null || true)"

    local filtered=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local file="${line%%:*}"
        local ok=0
        for a in "${allow_sites[@]}"; do
            if [[ "$file" == *"$a" ]]; then ok=1; break; fi
        done
        if [[ "$ok" -eq 0 ]]; then
            filtered+="$line"$'\n'
        fi
    done <<< "$hits"

    if [[ -n "${filtered// /}" && "$filtered" != $'\n' ]]; then
        say_fail "Rule 1: &http.Client{...} outside pkg/httpsec — swap for httpsec.SafeHTTPClient:"
        printf '%s' "$filtered" | sed 's/^/       /'
        return
    fi
    say_pass "Rule 1: no raw &http.Client{} outside pkg/httpsec (api/, agent/; 5 documented exceptions)"
}

# ---------------------------------------------------------------------------
# Rule 2: no dev-default secrets hardcoded anywhere the repo would ship.
#
# The AUTH_JWT_SECRET / APP_ENCRYPTION_KEY literals in docker-compose.yml
# are intentionally matched by the startup sentinel in
# api/internal/config/config.go — refuse to boot outside APP_ENV=development.
# If the literal appears in any OTHER place (.env.*.example copied too
# aggressively, handbook snippet, new compose file), the sentinel stops
# protecting and an ops team can ship the known value to prod.
# ---------------------------------------------------------------------------
check_dev_default_secrets() {
    local sentinels=(
        'this-is-a-development-secret-key-at-least-64-characters-long-for-security'
        'this-is-a-development-secret-key-at-least-32-characters'
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    )

    local allow=(
        # Expected: docker-compose.yml is the canonical dev bundle and
        # the sentinel check refuses to use these values outside dev.
        'docker-compose.yml'
        'docker-compose.monitoring.yml'
        'docker-compose.dev.yml'
        # Expected: config validator explicitly lists these as the
        # forbidden values — it MUST hold the exact literal.
        'api/internal/config/config.go'
        # Expected: security-lint script itself (this file).
        'scripts/security-lint.sh'
    )

    # tmp/ and build artefacts are local-only, never committed.
    local skip_globs=(
        '*/tmp/*'
        '*/node_modules/*'
        '*/.next/*'
        '*/dist/*'
        '*/build/*'
    )
    # Test files legitimately hard-code sentinel values to exercise
    # the sentinel check itself; the actual binary would never ship
    # with these tests baked into config.
    local skip_test_globs=(
        '*_test.go'
        '*.test.ts'
        '*.test.tsx'
        '*.spec.ts'
    )

    local f before_fail=$fail
    for s in "${sentinels[@]}"; do
        # -I: never match inside binaries. A locally-built ./api/server has the
        # dev sentinels compiled into it and would be reported as a source leak.
        hits="$(grep -RlFI "$s" \
            --exclude-dir='.git' \
            --exclude-dir='.claude' \
            --exclude-dir='vendor' \
            --exclude-dir='node_modules' \
            --exclude-dir='tmp' \
            --exclude-dir='.next' \
            --exclude-dir='dist' \
            --exclude-dir='build' \
            . 2>/dev/null || true)"

        while IFS= read -r f; do
            [[ -z "$f" ]] && continue

            # Skip test files (they legitimately use the sentinels as
            # fixtures to verify the startup guard).
            local is_test=0
            for g in "${skip_test_globs[@]}"; do
                if [[ "$f" == $g ]]; then is_test=1; break; fi
            done
            [[ "$is_test" -eq 1 ]] && continue

            # Skip .env files outside git — dev machines carry them.
            if [[ "$f" == *".env" || "$f" == *".env.local" ]]; then
                if command -v git >/dev/null 2>&1 && \
                   ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
                    continue # untracked local file, fine
                fi
            fi

            local ok=0
            for a in "${allow[@]}"; do
                if [[ "$f" == *"$a" ]]; then ok=1; break; fi
            done
            if [[ "$ok" -eq 0 ]]; then
                say_fail "Rule 2: dev-default secret $s found in $f (not on allow-list)"
            fi
        done <<< "$hits"
    done

    if [[ $fail -eq $before_fail ]]; then
        say_pass "Rule 2: no dev-default secrets outside docker-compose/config allow-list"
    fi
}

# ---------------------------------------------------------------------------
# Rule 3: .env files must not be tracked by git.
#
# .gitignore covers .env / .env.* but only for new commits; if an .env
# sneaked in earlier and the .gitignore was added later, `git ls-files`
# still lists it. This rule catches that residual case.
# ---------------------------------------------------------------------------
check_env_files_tracked() {
    if ! command -v git >/dev/null 2>&1; then
        say_warn "Rule 3: git not available; skipping .env tracked check"
        return
    fi
    local tracked
    tracked="$(git ls-files | grep -E '(^|/)\.env($|\.[^e])' | grep -v '\.example$' || true)"
    if [[ -n "$tracked" ]]; then
        say_fail "Rule 3: tracked .env file(s) in git (secrets risk):"
        echo "$tracked" | sed 's/^/       /'
        return
    fi
    say_pass "Rule 3: no tracked .env files in git"
}

# ---------------------------------------------------------------------------
# Rule 4: agent dangerousToolFlags must include the audit-required set.
#
# The audit (Pass-6 P6-1, P6-10) identified the flag classes attackers
# abuse for SSRF / path-traversal / privilege escalation via user-
# supplied ExtraArgs. If someone refactors the map and drops a flag,
# the runtime validator will silently permit that arg on the scanner
# CLI. We pin the minimum viable set here.
# ---------------------------------------------------------------------------
check_agent_dangerous_flags() {
    local f="agent/internal/executor/vulnscan.go"
    if [[ ! -f "$f" ]]; then
        say_skip "Rule 4: $f not found; cannot verify agent dangerous-flag set"
        return
    fi
    local required=(
        '"-proxy"' '"--proxy"'
        '"-c"' '"--config"'
        '"-t"' '"--templates"'
        '"-r"' '"--resolvers"'
        '"--interactsh-url"'
        '"--headless"'
    )
    local missing=()
    for flag in "${required[@]}"; do
        if ! grep -qF "$flag" "$f"; then
            missing+=("$flag")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        say_fail "Rule 4: agent dangerousToolFlags missing required entries: ${missing[*]}"
        return
    fi
    say_pass "Rule 4: agent dangerousToolFlags contains required SSRF/RCE flag set"
}

# ---------------------------------------------------------------------------
# Rule 5: httpsec package must be used by every outbound-client site
# that the audit flagged. Not strictly a leak — a gentle reminder for
# the next PR author that these files are load-bearing.
# ---------------------------------------------------------------------------
check_httpsec_used() {
    local required=(
        # API outbound clients — tenant-configurable URLs.
        'api/internal/infra/llm/claude.go'
        'api/internal/infra/llm/gemini.go'
        'api/internal/infra/llm/openai.go'
        'api/internal/infra/notifier/slack.go'
        'api/internal/infra/notifier/teams.go'
        'api/internal/infra/notifier/telegram.go'
        'api/internal/infra/notifier/webhook.go'
        'api/internal/infra/jira/client.go'
        'api/internal/app/auth/sso.go'
        'api/internal/app/auth/oauth.go'
        'api/internal/app/threat/intel_service.go'
        'api/internal/app/threat/intel_refresher.go'
        'api/pkg/keycloak/validator.go'
    )
    # sdk-go was meant to get a mirror of pkg/httpsec. An earlier version of
    # this rule listed these files as required and described the mirror as
    # done. It is not: sdk-go/pkg/httpsec exists neither locally nor upstream,
    # so these seven outbound clients have no SSRF guard. The rule asserted a
    # control that was never built, and because this script ran in a repository
    # that does not exist on GitHub, it never got the chance to say so.
    local sdk_gap=(
        'sdk-go/pkg/client/client.go'
        'sdk-go/pkg/core/base_collector.go'
        'sdk-go/pkg/enrichers/kev/kev.go'
        'sdk-go/pkg/enrichers/epss/epss.go'
        'sdk-go/pkg/platform/lease.go'
        'sdk-go/pkg/platform/bootstrap.go'
        'sdk-go/pkg/platform/poller.go'
    )
    local missing=()
    for f in "${required[@]}"; do
        if [[ -f "$f" ]] && ! grep -q 'httpsec' "$f"; then
            missing+=("$f")
        fi
    done
    local gap=()
    for f in "${sdk_gap[@]}"; do
        if [[ -f "$f" ]] && ! grep -q 'httpsec' "$f"; then
            gap+=("$f")
        fi
    done
    if [[ ${#gap[@]} -gt 0 ]]; then
        say_gap "Rule 5: sdk-go/pkg/httpsec does not exist; ${#gap[@]} sdk-go outbound clients are unguarded (tracked, not blocking)"
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        say_fail "Rule 5: expected httpsec import missing in: ${missing[*]}"
        return
    fi
    say_pass "Rule 5: httpsec wired in all api outbound client sites"
}

# ---------------------------------------------------------------------------
# Rule 6: api/pkg/httpsec and sdk-go/pkg/httpsec blocklists must match.
# The two packages are independent copies (cross-module). Drift means
# one tree becomes more permissive than the other — a DoS waiting to
# happen.
#
# Covers both tables: hardBlockedIPRanges (always-blocked — cloud
# IMDS, loopback, CGNAT, multicast) AND privateIPRanges (RFC1918 /
# ULA, blocked by default but opt-in via env). If either drifts
# between api/ and sdk-go/ the on-prem story breaks in asymmetric
# ways, which is worse than just one side being wrong.
# ---------------------------------------------------------------------------
check_httpsec_drift() {
    local api_file='api/pkg/httpsec/ssrf.go'
    local sdk_file='sdk-go/pkg/httpsec/ssrf.go'
    if [[ ! -f "$api_file" || ! -f "$sdk_file" ]]; then
        say_gap "Rule 6: $sdk_file does not exist, so there is no second CIDR table to compare (tracked, not blocking)"
        return
    fi

    local tables=(hardBlockedIPRanges privateIPRanges)
    local any_drift=0
    for t in "${tables[@]}"; do
        if ! diff <(awk "/^var ${t} /,/^}/" "$api_file") \
                  <(awk "/^var ${t} /,/^}/" "$sdk_file") > /dev/null; then
            say_fail "Rule 6: ${t} drift between $api_file and $sdk_file"
            diff <(awk "/^var ${t} /,/^}/" "$api_file") \
                 <(awk "/^var ${t} /,/^}/" "$sdk_file") | sed 's/^/       /'
            any_drift=1
        fi
    done
    if [[ $any_drift -eq 0 ]]; then
        say_pass "Rule 6: api and sdk-go httpsec CIDR tables agree (hardBlockedIPRanges, privateIPRanges)"
    fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
printf '== security-lint ==\n'

# Preflight. Rule 1 greps 'api/ agent/' and tolerates a missing path, so an
# absent sibling would quietly shrink its search space rather than fail. Check
# the layout up front instead of trusting each rule to notice.
for sibling in api agent sdk-go; do
    if [[ ! -d "$ROOT/$sibling" ]]; then
        say_skip "workspace is missing $sibling/ (looked in $ROOT) — rules covering it cannot run"
    fi
done

check_http_client
check_dev_default_secrets
check_env_files_tracked
check_agent_dangerous_flags
check_httpsec_used
check_httpsec_drift
printf '\n'
if [[ $fail -ne 0 ]]; then
    printf '%sSecurity lint FAILED.%s Fix the rules above before merging.\n' "$RED" "$RST"
    exit 1
fi
printf '%sSecurity lint passed.%s\n' "$GRN" "$RST"
exit 0
