#!/usr/bin/env bash
# ================================================================
# Asset Identity Resolution - Comprehensive Test Script
# RFC-001: Tests normalization, dedup, and edge cases
# ================================================================
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8080}"
TOTAL=0
PASSED=0
FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Auth - get token
TOKEN="${API_TOKEN:-}"
if [ -z "$TOKEN" ]; then
    echo "Set API_TOKEN env var or export it before running tests"
    echo "Example: export API_TOKEN=\$(curl -s $API_BASE/api/v1/auth/login -d '{...}' | jq -r .token)"
    exit 1
fi

AUTH="Authorization: Bearer $TOKEN"

# ─── Helpers ──────────────────────────────────────────────────

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

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$haystack" | grep -q "$needle"; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}PASS${NC} $desc"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}FAIL${NC} $desc"
        echo -e "       expected to contain: ${YELLOW}$needle${NC}"
    fi
}

create_asset() {
    local name="$1" type="$2"
    local resp
    resp=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/api/v1/assets" \
        -H "$AUTH" -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\", \"asset_type\": \"$type\", \"criticality\": \"medium\"}")
    echo "$resp"
}

get_asset() {
    local id="$1"
    curl -s "$API_BASE/api/v1/assets/$id" -H "$AUTH"
}

search_assets() {
    local search="$1"
    curl -s "$API_BASE/api/v1/assets?search=$search&per_page=50" -H "$AUTH"
}

delete_asset() {
    local id="$1"
    curl -s -X DELETE "$API_BASE/api/v1/assets/$id" -H "$AUTH" -o /dev/null
}

cleanup_test_assets() {
    # Delete assets created during tests
    local ids
    ids=$(curl -s "$API_BASE/api/v1/assets?search=test-normalize&per_page=100" -H "$AUTH" | jq -r '.data[]?.id // empty')
    for id in $ids; do
        delete_asset "$id"
    done
}

# ─── Test Suite ───────────────────────────────────────────────

echo "================================================================"
echo " Asset Identity Resolution - Test Suite"
echo " RFC-001: Normalization & Deduplication"
echo "================================================================"
echo ""

# Cleanup before tests
cleanup_test_assets

# ── Test 1: Domain case normalization ──
echo "Test 1: Domain case normalization"
resp=$(create_asset "test-normalize-EXAMPLE.COM" "domain")
code=$(echo "$resp" | tail -1)
body=$(echo "$resp" | sed '$d')
assert_eq "domain created" "201" "$code"
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "domain name normalized to lowercase" "test-normalize-example.com" "$name"
    delete_asset "$id"
fi

# ── Test 2: Domain trailing dot ──
echo "Test 2: Domain trailing dot stripped"
resp=$(create_asset "test-normalize-trailing.com." "domain")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "trailing dot stripped" "test-normalize-trailing.com" "$name"
    delete_asset "$id"
fi

# ── Test 3: Domain dedup — same name different case ──
echo "Test 3: Domain case dedup"
resp1=$(create_asset "test-normalize-dedup.com" "domain")
body1=$(echo "$resp1" | sed '$d')
id1=$(echo "$body1" | jq -r '.id // empty')

resp2=$(create_asset "test-normalize-DEDUP.COM" "domain")
code2=$(echo "$resp2" | tail -1)
body2=$(echo "$resp2" | sed '$d')

# Should either return same asset or conflict
results=$(search_assets "test-normalize-dedup.com")
count=$(echo "$results" | jq '.total // 0')
assert_eq "only 1 domain exists (dedup by case)" "1" "$count"

# Cleanup
if [ -n "$id1" ]; then delete_asset "$id1"; fi
id2=$(echo "$body2" | jq -r '.id // empty')
if [ -n "$id2" ] && [ "$id2" != "$id1" ]; then delete_asset "$id2"; fi

# ── Test 4: Host normalization ──
echo "Test 4: Host name normalization"
resp=$(create_asset "test-normalize-Web-Server-01.CORP.local." "host")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "host normalized" "test-normalize-web-server-01.corp.local" "$name"
    delete_asset "$id"
fi

# ── Test 5: Repository normalization ──
echo "Test 5: Repository format normalization"
resp=$(create_asset "https://github.com/Test-Normalize-Org/Repo.git" "repository")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "repo normalized" "github.com/test-normalize-org/repo" "$name"
    delete_asset "$id"
fi

# ── Test 6: IP address normalization ──
echo "Test 6: IP address normalization"
resp=$(create_asset "192.168.1.1" "ip_address")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "IPv4 unchanged" "192.168.1.1" "$name"
    delete_asset "$id"
fi

# ── Test 7: Subdomain with protocol stripped ──
echo "Test 7: Subdomain protocol stripped"
resp=$(create_asset "https://test-normalize-api.example.com" "subdomain")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "protocol stripped" "test-normalize-api.example.com" "$name"
    delete_asset "$id"
fi

# ── Test 8: URL application normalization ──
echo "Test 8: Application URL normalization"
resp=$(create_asset "HTTPS://test-normalize-APP.Example.COM:443/v1/" "application")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "URL normalized" "https://test-normalize-app.example.com/v1" "$name"
    delete_asset "$id"
fi

# ── Test 9: Database connection string normalization ──
echo "Test 9: Database name normalization"
resp=$(create_asset "postgres://user:pass@test-normalize-DB.example.com:5432/mydb?ssl=true" "database")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "db normalized (credentials stripped)" "test-normalize-db.example.com:5432/mydb" "$name"
    delete_asset "$id"
fi

# ── Test 10: Network CIDR normalization ──
echo "Test 10: Network CIDR normalization"
resp=$(create_asset "192.168.1.100/24" "network")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "CIDR host bits zeroed" "192.168.1.0/24" "$name"
    delete_asset "$id"
fi

# ── Test 11: S3 bucket normalization ──
echo "Test 11: S3 bucket name normalization"
resp=$(create_asset "s3://test-normalize-My-Bucket" "storage")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "s3 prefix stripped, lowercase" "test-normalize-my-bucket" "$name"
    delete_asset "$id"
fi

# ── Test 12: Rename preserves alias ──
echo "Test 12: Rename stores old name as alias"
resp=$(create_asset "test-normalize-old-name.com" "domain")
body=$(echo "$resp" | sed '$d')
id=$(echo "$body" | jq -r '.id // empty')
if [ -n "$id" ]; then
    # Update name
    curl -s -X PATCH "$API_BASE/api/v1/assets/$id" \
        -H "$AUTH" -H "Content-Type: application/json" \
        -d '{"name": "test-normalize-new-name.com"}' -o /dev/null

    asset=$(get_asset "$id")
    name=$(echo "$asset" | jq -r '.name')
    assert_eq "name updated" "test-normalize-new-name.com" "$name"

    # Check alias
    aliases=$(echo "$asset" | jq -r '.properties.aliases // [] | join(",")')
    assert_contains "old name in aliases" "test-normalize-old-name.com" "$aliases"

    delete_asset "$id"
fi

# Cleanup
cleanup_test_assets

# ── Summary ──
echo ""
echo "================================================================"
echo -e " Results: ${GREEN}$PASSED passed${NC} / ${RED}$FAILED failed${NC} / $TOTAL total"
echo "================================================================"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
