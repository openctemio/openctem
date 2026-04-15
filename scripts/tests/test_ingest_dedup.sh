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

ingest_report() {
    local payload="$1"
    curl -s -w "\n%{http_code}" -X POST "$API_BASE/api/v1/ingest" \
        -H "$AUTH" -H "Content-Type: application/json" \
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

# ── Test 1: Domain case dedup through ingest ──
echo "Test 1: Domain case dedup through ingest"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "d1", "type": "domain", "name": "ingest-dedup-TEST.example.com"},
        {"id": "d2", "type": "domain", "name": "ingest-dedup-test.example.com"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "ingest-dedup-test.example.com")
assert_eq "2 domains same name (case) → 1 asset" "1" "$count"

# ── Test 2: Domain trailing dot dedup ──
echo "Test 2: Domain trailing dot dedup"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "d3", "type": "domain", "name": "ingest-dedup-dot.example.com."},
        {"id": "d4", "type": "domain", "name": "ingest-dedup-dot.example.com"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "ingest-dedup-dot.example.com")
assert_eq "domain with/without trailing dot → 1 asset" "1" "$count"

# ── Test 3: Repository format dedup ──
echo "Test 3: Repository format normalization"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "r1", "type": "repository", "name": "https://github.com/ingest-dedup-Org/Repo.git"},
        {"id": "r2", "type": "repository", "name": "github.com/ingest-dedup-org/repo"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "ingest-dedup-org/repo")
assert_eq "repo HTTPS+.git vs plain → 1 asset" "1" "$count"

# ── Test 4: Host normalization ──
echo "Test 4: Host name case normalization"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "h1", "type": "host", "name": "ingest-dedup-Web-Server.CORP.local"},
        {"id": "h2", "type": "host", "name": "ingest-dedup-web-server.corp.local"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "ingest-dedup-web-server.corp.local")
assert_eq "host case variation → 1 asset" "1" "$count"

# ── Test 5: IP address normalization ──
echo "Test 5: IP address as asset"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "ip1", "type": "ip_address", "value": "10.99.99.1"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "10.99.99.1")
assert_eq "IP address created" "1" "$count"

# ── Test 6: Subdomain normalization ──
echo "Test 6: Subdomain normalization"
ingest_report '{
    "format": "ctis",
    "version": "1.0",
    "tool": {"name": "test-dedup", "version": "1.0"},
    "assets": [
        {"id": "s1", "type": "subdomain", "name": "ingest-dedup-API.EXAMPLE.COM."},
        {"id": "s2", "type": "subdomain", "name": "ingest-dedup-api.example.com"}
    ]
}' > /dev/null 2>&1

count=$(count_assets "ingest-dedup-api.example.com")
assert_eq "subdomain case+dot → 1 asset" "1" "$count"

# ── Test 7: Multiple ingests same domain ──
echo "Test 7: Multiple ingests same domain (idempotent)"
for i in 1 2 3; do
    ingest_report "{
        \"format\": \"ctis\",
        \"version\": \"1.0\",
        \"tool\": {\"name\": \"test-dedup-round$i\", \"version\": \"1.0\"},
        \"assets\": [
            {\"id\": \"repeat1\", \"type\": \"domain\", \"name\": \"ingest-dedup-repeat.example.com\"}
        ]
    }" > /dev/null 2>&1
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
