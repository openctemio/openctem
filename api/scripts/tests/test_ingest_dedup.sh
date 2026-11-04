#!/usr/bin/env bash
# ================================================================
# Ingest Dedup Test Script
# RFC-001: Tests asset dedup through the ingest API
# ================================================================
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8080}"
TOTAL=0
PASSED=0
FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOKEN="${API_TOKEN:-}"
if [ -z "$TOKEN" ]; then
    echo "Set API_TOKEN env var before running"
    exit 1
fi

AUTH="Authorization: Bearer $TOKEN"

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}PASS${NC} $desc"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}FAIL${NC} $desc"
        echo -e "       expected: ${YELLOW}$expected${NC}"
        echo -e "       actual:   ${YELLOW}$actual${NC}"
    fi
}

# A fresh lowercase UUIDv7 (CTIS 2.0 metadata.id, the producer's idempotency key).
new_report_id() {
    local ms; ms=$(( $(date +%s%N) / 1000000 ))
    printf '%08x-%04x-7%03x-%x%03x-%04x%08x' \
        $(( ms >> 16 )) $(( ms & 0xffff )) $(( RANDOM % 4096 )) $(( 8 + RANDOM % 4 )) $(( RANDOM % 4096 )) $RANDOM $(( (RANDOM << 15) | RANDOM ))
}

# ingest_report <assets-json-array>: send a valid CTIS 2.0 document with the
# given assets. Values must be in the canonical form of their type (the
# receiver refuses anything else); the HTTP status is the last output line.
ingest_report() {
    local assets="$1" tool="${2:-test-dedup}"
    local payload
    payload=$(printf '{"version":"2.0","metadata":{"id":"%s","generated_at":"%s","channel":"scanner","coverage_type":"partial"},"tool":{"name":"%s","version":"1.0"},"assets":%s}' \
        "$(new_report_id)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$tool" "$assets")
    echo "$payload" | python3 -I -c 'import json,sys; json.load(sys.stdin)' || echo "invalid test payload" >&2
    curl -s -w "\n%{http_code}" -X POST "$API_BASE/api/v1/ingest" \
        -H "$AUTH" -H "Content-Type: application/vnd.ctis+json; version=2.0" \
        -d "$payload"
}

search_assets() {
    curl -s "$API_BASE/api/v1/assets?search=$1&per_page=100" -H "$AUTH"
}

count_assets() {
    local search="$1"
    curl -s "$API_BASE/api/v1/assets?search=$search&per_page=1" -H "$AUTH" | jq '.total // 0'
}

echo "================================================================"
echo " Ingest Dedup Test Suite"
echo " RFC-001: Asset Identity Resolution through Ingest API"
echo "================================================================"
echo ""

# CTIS 2.0 documents carry values in the canonical form of their type, so a
# duplicate is the same canonical asset sent twice (two documents, or two
# tools), never a spelling variant; a non-canonical spelling is refused.

# ── Test 1: same domain reported by two documents ──
echo "Test 1: Domain reported twice"
ingest_report '[{"id": "d1", "type": "domain_name", "value": "ingest-dedup-test.example.com"}]' > /dev/null 2>&1
ingest_report '[{"id": "d2", "type": "domain_name", "value": "ingest-dedup-test.example.com"}]' test-dedup-b > /dev/null 2>&1

count=$(count_assets "ingest-dedup-test.example.com")
assert_eq "2 documents same domain → 1 asset" "1" "$count"

# ── Test 2: non-canonical domain spelling is refused ──
echo "Test 2: Non-canonical domain is refused"
code=$(ingest_report '[{"id": "d3", "type": "domain_name", "value": "ingest-dedup-DOT.example.com."}]' 2>/dev/null | tail -n1)
assert_eq "upper-case + trailing dot → 422" "422" "$code"
count=$(count_assets "ingest-dedup-dot.example.com")
assert_eq "refused document created no asset" "0" "$count"

# ── Test 3: Repository canonical form ──
echo "Test 3: Repository canonical form"
ingest_report '[{"id": "r1", "type": "repository", "value": "github.com/ingest-dedup-org/repo"}]' > /dev/null 2>&1
ingest_report '[{"id": "r2", "type": "repository", "value": "github.com/ingest-dedup-org/repo"}]' test-dedup-b > /dev/null 2>&1
code=$(ingest_report '[{"id": "r3", "type": "repository", "value": "https://github.com/ingest-dedup-Org/Repo.git"}]' 2>/dev/null | tail -n1)
assert_eq "URL + .git form → 422" "422" "$code"

count=$(count_assets "ingest-dedup-org/repo")
assert_eq "repo reported twice → 1 asset" "1" "$count"

# ── Test 4: Host reported twice ──
echo "Test 4: Host reported twice"
ingest_report '[{"id": "h1", "type": "host", "value": "ingest-dedup-web-server.corp.local"}]' > /dev/null 2>&1
ingest_report '[{"id": "h2", "type": "host", "value": "ingest-dedup-web-server.corp.local"}]' test-dedup-b > /dev/null 2>&1

count=$(count_assets "ingest-dedup-web-server.corp.local")
assert_eq "host reported twice → 1 asset" "1" "$count"

# ── Test 5: IP address ──
echo "Test 5: IP address as asset"
ingest_report '[{"id": "ip1", "type": "ip_address", "value": "10.99.99.1"}]' > /dev/null 2>&1

count=$(count_assets "10.99.99.1")
assert_eq "IP address created" "1" "$count"

# ── Test 6: Subdomain (a domain_name below its apex) ──
echo "Test 6: Subdomain reported twice"
ingest_report '[{"id": "s1", "type": "domain_name", "value": "ingest-dedup-api.example.com"}]' > /dev/null 2>&1
ingest_report '[{"id": "s2", "type": "domain_name", "value": "ingest-dedup-api.example.com"}]' test-dedup-b > /dev/null 2>&1

count=$(count_assets "ingest-dedup-api.example.com")
assert_eq "subdomain reported twice → 1 asset" "1" "$count"

# ── Test 7: Multiple ingests same domain ──
echo "Test 7: Multiple ingests same domain (idempotent)"
for i in 1 2 3; do
    ingest_report '[{"id": "repeat1", "type": "domain_name", "value": "ingest-dedup-repeat.example.com"}]' "test-dedup-round$i" > /dev/null 2>&1
done

count=$(count_assets "ingest-dedup-repeat.example.com")
assert_eq "3 ingests same domain → still 1 asset" "1" "$count"

# ── Summary ──
echo ""
echo "================================================================"
echo -e " Results: ${GREEN}$PASSED passed${NC} / ${RED}$FAILED failed${NC} / $TOTAL total"
echo "================================================================"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
