#!/bin/bash
# =============================================================================
# Integration Test: Asset Consolidation Full Flow
# =============================================================================
# Tests: type consolidation, sub_type, properties filter, facets, promote
# Usage: bash tests/integration/test_asset_consolidation.sh
# Requires: API running on localhost:8080, admin@openctem.io account
# =============================================================================

set -e
PASS=0
FAIL=0
API="http://localhost:8080/api/v1"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo -e "  ${GREEN}PASS${NC} $desc (got: $actual)"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}FAIL${NC} $desc (expected: $expected, got: $actual)"
    FAIL=$((FAIL+1))
  fi
}

assert_gt() {
  local desc="$1" min="$2" actual="$3"
  if [ "$actual" -gt "$min" ] 2>/dev/null; then
    echo -e "  ${GREEN}PASS${NC} $desc (got: $actual > $min)"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}FAIL${NC} $desc (expected > $min, got: $actual)"
    FAIL=$((FAIL+1))
  fi
}

# === AUTH ===
echo "=== Authenticating ==="
LOGIN_RESP=$(curl -s "$API/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"admin@openctem.io","password":"Admin@123"}')

REFRESH=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
TENANT_ID=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; ts=json.load(sys.stdin).get('tenants',[]); print(ts[0]['id'] if ts else '')" 2>/dev/null)

TOKEN=$(curl -s "$API/auth/token" -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\",\"tenant_id\":\"$TENANT_ID\"}" | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

AUTH="Authorization: Bearer $TOKEN"

if [ -z "$TOKEN" ] || [ "$TOKEN" = "None" ]; then
  echo -e "${RED}FAIL: Could not authenticate${NC}"
  exit 1
fi
echo "  Authenticated as admin, tenant=$TENANT_ID"

# === 1. STATS ENDPOINT ===
echo ""
echo "=== 1. Asset Stats ==="

# Stats without filter
STATS=$(curl -s "$API/assets/stats" -H "$AUTH")
TOTAL=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
TYPE_COUNT=$(echo "$STATS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['by_type']))")
SUB_TYPE_COUNT=$(echo "$STATS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('by_sub_type',{})))")
assert_gt "total assets" 0 "$TOTAL"
assert_gt "type count" 5 "$TYPE_COUNT"
assert_gt "sub_type count" 5 "$SUB_TYPE_COUNT"

# Stats with sub_type filter
FW_TOTAL=$(curl -s "$API/assets/stats?types=network&sub_type=firewall" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
assert_gt "firewall count" 0 "$FW_TOTAL"

NET_TOTAL=$(curl -s "$API/assets/stats?types=network" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
assert_gt "network total > firewall" "$FW_TOTAL" "$NET_TOTAL"

# === 2. FACETS ENDPOINT ===
echo ""
echo "=== 2. Property Facets ==="

FACET_COUNT=$(curl -s "$API/assets/facets?types=network" -H "$AUTH" | \
  python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
assert_gt "network facets" 3 "$FACET_COUNT"

HOST_FACETS=$(curl -s "$API/assets/facets?types=host" -H "$AUTH" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join([f['Key'] for f in d]))")
echo "  Host facet keys: $HOST_FACETS"
assert_gt "host facets" 0 "$(echo "$HOST_FACETS" | tr ',' '\n' | wc -l)"

# === 3. PROPERTIES FILTER ===
echo ""
echo "=== 3. Properties Filter ==="

# Filter by vendor
CISCO_COUNT=$(curl -s "$API/assets?types=network&properties=vendor:Cisco&per_page=1" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
assert_gt "Cisco network devices" 0 "$CISCO_COUNT"

# Filter by non-existent value
NONE_COUNT=$(curl -s "$API/assets?types=network&properties=vendor:NonExistent&per_page=1" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
assert_eq "non-existent vendor" "0" "$NONE_COUNT"

# Multi-filter
MULTI=$(curl -s "$API/assets?types=network&properties=vendor:Cisco,model:Catalyst%209500&per_page=1" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
echo "  Multi-filter (vendor:Cisco,model:Catalyst 9500): $MULTI"

# === 4. PROMOTE PROPERTIES ON CREATE ===
echo ""
echo "=== 4. Promote Properties on Create ==="

TS=$(date +%s)
CREATE_RESP=$(curl -s -X POST "$API/assets" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"name\": \"test-promote-$TS\",
  \"type\": \"network\",
  \"criticality\": \"medium\",
  \"properties\": {
    \"sub_type\": \"firewall\",
    \"vendor\": \"TestVendor\",
    \"scope\": \"internal\"
  }
}")

CREATED_TYPE=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type',''))")
CREATED_SUB=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sub_type',''))")
CREATED_SCOPE=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))")
CREATED_VENDOR=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('properties',{}).get('vendor',''))")
CREATED_ID=$(echo "$CREATE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")

assert_eq "promoted type" "network" "$CREATED_TYPE"
assert_eq "promoted sub_type" "firewall" "$CREATED_SUB"
assert_eq "promoted scope" "internal" "$CREATED_SCOPE"
assert_eq "vendor in properties" "TestVendor" "$CREATED_VENDOR"

# Test type alias promotion
CREATE_ALIAS=$(curl -s -X POST "$API/assets" -H "$AUTH" -H "Content-Type: application/json" -d "{
  \"name\": \"test-alias-$TS\",
  \"type\": \"host\",
  \"criticality\": \"low\",
  \"properties\": {
    \"type\": \"firewall\",
    \"vendor\": \"AliasTest\"
  }
}")

ALIAS_TYPE=$(echo "$CREATE_ALIAS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type',''))")
ALIAS_SUB=$(echo "$CREATE_ALIAS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sub_type',''))")
ALIAS_ID=$(echo "$CREATE_ALIAS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")

assert_eq "alias resolved type" "network" "$ALIAS_TYPE"
assert_eq "alias resolved sub_type" "firewall" "$ALIAS_SUB"

# === 5. IDENTITY PAGE ===
echo ""
echo "=== 5. Identity Type ==="

ID_COUNT=$(curl -s "$API/assets?types=identity&per_page=1" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
assert_gt "identity assets" 0 "$ID_COUNT"

ID_SUB=$(curl -s "$API/assets?types=identity&sub_type=iam_user&per_page=1" -H "$AUTH" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
echo "  identity/iam_user count: $ID_SUB"

# === 6. MODULES ===
echo ""
echo "=== 6. Modules ==="

MOD_COUNT=$(curl -s "$API/me/modules" -H "$AUTH" | \
  python3 -c "import sys,json; print(len(json.load(sys.stdin).get('sub_modules',{}).get('assets',[])))")
assert_gt "asset sub-modules" 15 "$MOD_COUNT"

IDENTITY_MOD=$(curl -s "$API/me/modules" -H "$AUTH" | \
  python3 -c "import sys,json; subs=json.load(sys.stdin).get('sub_modules',{}).get('assets',[]); print('found' if any(s['slug']=='identity' for s in subs) else 'missing')")
assert_eq "identity module" "found" "$IDENTITY_MOD"

# === 7. CLEANUP ===
echo ""
echo "=== 7. Cleanup test assets ==="
if [ -n "$CREATED_ID" ]; then
  curl -s -X DELETE "$API/assets/$CREATED_ID" -H "$AUTH" > /dev/null 2>&1
  echo "  Deleted test-promote-$TS"
fi
if [ -n "$ALIAS_ID" ]; then
  curl -s -X DELETE "$API/assets/$ALIAS_ID" -H "$AUTH" > /dev/null 2>&1
  echo "  Deleted test-alias-$TS"
fi

# === SUMMARY ===
echo ""
echo "============================================"
echo -e "  ${GREEN}PASSED: $PASS${NC}  ${RED}FAILED: $FAIL${NC}"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
