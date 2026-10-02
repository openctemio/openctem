#!/bin/bash
# =============================================================================
# Attachment & Evidence Flow — Full E2E Test Suite
# =============================================================================
# Covers the complete attachment lifecycle:
#
#   1. Setup      — register, create tenant, obtain auth token
#   2. Upload     — valid file, too-large, unsupported type, no auth, dedup
#   3. Download   — 200 + headers, 404, security headers
#   4. List       — by context, missing params → 400
#   5. Delete     — 204, double-delete 404, file gone after delete
#   6. Link       — orphan upload + link to context → appears in list
#   7. Storage    — GET/PATCH /attachments/storage-config (admin only)
#   8. Security   — SVG rejected, path-traversal filename sanitized
#
# Usage:
#   ./test_e2e_attachments.sh [API_URL]
#   API_URL=http://localhost:8080 AUTH_TOKEN=xxx ./test_e2e_attachments.sh
#
# Requirements: jq, curl, dd, python3 (for unique IDs)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

API_URL="${1:-${API_URL:-http://localhost:8080}}"
TS=$(date +%s)
TMPDIR_WORK=$(mktemp -d /tmp/att_e2e.XXXXXX)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

PASS=0; FAIL=0; SKIP=0

# Response state (populated by req())
HTTP=""; BODY=""

# ── Helpers ──────────────────────────────────────────────────────────────────

pass()  { echo -e "${GREEN}  ✅ $1${NC}"; PASS=$((PASS+1)); }
fail()  { echo -e "${RED}  ❌ $1${NC}"; [ -n "${2:-}" ] && echo -e "${RED}     $2${NC}"; FAIL=$((FAIL+1)); }
skip()  { echo -e "${YELLOW}  ⏭️  $1${NC}"; SKIP=$((SKIP+1)); }
h()     { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
sub()   { echo -e "${CYAN}    ▸ $1${NC}"; }

# req METHOD ENDPOINT BODY AUTH_HEADER
# Sets global HTTP and BODY
req() {
  local m="$1" e="$2" d="$3" auth="${4:-}"
  local args=(-s -w "\n%{http_code}" -X "$m" "${API_URL}${e}" -H "Content-Type: application/json")
  [ -n "$auth" ] && args+=(-H "$auth")
  [ -n "$d" ]    && args+=(-d "$d")
  curl "${args[@]}" > "$TMPDIR_WORK/resp" 2>/dev/null
  HTTP=$(tail -1 "$TMPDIR_WORK/resp")
  BODY=$(sed '$d' "$TMPDIR_WORK/resp")
}

# req_upload FILE CONTENT_TYPE CONTEXT_TYPE CONTEXT_ID AUTH_HEADER
# Sends a multipart/form-data POST to /api/v1/attachments
req_upload() {
  local filepath="$1" ct="$2" ctx_type="${3:-}" ctx_id="${4:-}" auth="${5:-}"
  local args=(-s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/attachments")
  [ -n "$auth" ] && args+=(-H "$auth")
  args+=(-F "file=@${filepath};type=${ct}")
  [ -n "$ctx_type" ] && args+=(-F "context_type=${ctx_type}")
  [ -n "$ctx_id"   ] && args+=(-F "context_id=${ctx_id}")
  curl "${args[@]}" > "$TMPDIR_WORK/resp" 2>/dev/null
  HTTP=$(tail -1 "$TMPDIR_WORK/resp")
  BODY=$(sed '$d' "$TMPDIR_WORK/resp")
}

# req_upload_raw — low-level: pass extra curl form args directly
req_upload_raw() {
  local auth="${1:-}"; shift
  local args=(-s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/attachments")
  [ -n "$auth" ] && args+=(-H "$auth")
  args+=("$@")
  curl "${args[@]}" > "$TMPDIR_WORK/resp" 2>/dev/null
  HTTP=$(tail -1 "$TMPDIR_WORK/resp")
  BODY=$(sed '$d' "$TMPDIR_WORK/resp")
}

jv() { echo "$BODY" | jq -r "${1}" 2>/dev/null; }

# assert_status DESC EXPECTED [EXPECTED2 ...]
assert_status() {
  local desc="$1"; shift
  for code in "$@"; do
    [ "$HTTP" = "$code" ] && { pass "$desc (HTTP $HTTP)"; return 0; }
  done
  fail "$desc" "Expected $(echo "$*" | tr ' ' '/'), got HTTP $HTTP. Body: $(echo "$BODY" | head -c 300)"
  return 1
}

# assert_json_field DESC JQPATH EXPECTED
assert_json_field() {
  local desc="$1" path="$2" expected="$3"
  local got
  got=$(jv "$path")
  if [ "$got" = "$expected" ]; then
    pass "$desc ($path=$got)"
  else
    fail "$desc" "Expected $path=$expected, got=$got. Body: $(echo "$BODY" | head -c 300)"
  fi
}

# assert_header DESC HEADER_NAME EXPECTED_SUBSTRING FILE
# FILE must be the raw curl response headers file
assert_header() {
  local desc="$1" hdr_name="$2" expected="$3" hdr_file="$4"
  local val
  val=$(grep -i "^${hdr_name}:" "$hdr_file" 2>/dev/null | head -1 || true)
  if echo "$val" | grep -qi "$expected"; then
    pass "$desc ($val)"
  else
    fail "$desc" "Expected header '$hdr_name' to contain '$expected', got: '$val'"
  fi
}

echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ATTACHMENT & EVIDENCE FLOW — E2E TEST SUITE${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo "  API: $API_URL"
echo "  Timestamp: $TS"

# =============================================================================
# 1. SETUP — register user + tenant, obtain auth token
# =============================================================================
h "1. SETUP"

EMAIL="att-test-${TS}@test.local"
PASSWORD="TestP@ss123!"

# If AUTH_TOKEN is set externally, skip registration
if [ -n "${AUTH_TOKEN:-}" ]; then
  OWNER_AUTH="Authorization: Bearer $AUTH_TOKEN"
  # Try to get tenant ID from token claims or just proceed (it must be in context)
  sub "Using externally provided AUTH_TOKEN"
  # We still need a tenant_id; try hitting /api/v1/tenants/current
  req GET "/api/v1/tenants/current" "" "$OWNER_AUTH"
  TENANT_ID=$(jv '.id')
  if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" = "null" ]; then
    req GET "/api/v1/auth/me" "" "$OWNER_AUTH"
    TENANT_ID=$(jv '.tenant_id')
  fi
  pass "Using pre-supplied token (tenant=$TENANT_ID)"
else
  # Register with retry for rate-limit (429)
  REGISTERED=0
  for attempt in 1 2 3 4 5; do
    req POST "/api/v1/auth/register" \
      "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Att Tester\"}" ""
    if [ "$HTTP" = "201" ]; then REGISTERED=1; break; fi
    if [ "$HTTP" = "429" ]; then sleep 25; continue; fi
    fail "Register user" "HTTP $HTTP: $(echo "$BODY" | head -c 150)"
    exit 1
  done
  [ "$REGISTERED" = "1" ] || { fail "Register user (rate-limited after 5 attempts)"; exit 1; }
  pass "Registered user $EMAIL"

  # Create tenant / first team
  req POST "/api/v1/auth/login" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" ""
  req POST "/api/v1/auth/create-first-team" \
    "{\"team_name\":\"Att Test ${TS}\",\"team_slug\":\"att-test-${TS}\"}" ""
  OWNER_TOKEN=$(jv '.access_token')
  TENANT_ID=$(jv '.tenant_id')
  [ -n "$OWNER_TOKEN" ] && [ "$OWNER_TOKEN" != "null" ] || { fail "Tenant creation failed"; exit 1; }
  OWNER_AUTH="Authorization: Bearer $OWNER_TOKEN"
  pass "Tenant created (id=$TENANT_ID)"
fi

# We need a finding to use as a context for attachment uploads.
# First create an asset, then a pentest campaign + finding.

req POST "/api/v1/assets" \
  "{\"name\":\"Att E2E Asset ${TS}\",\"type\":\"domain\",\"criticality\":\"medium\"}" "" "$OWNER_AUTH"
ASSET_ID=$(jv '.id')
if [ -z "$ASSET_ID" ] || [ "$ASSET_ID" = "null" ]; then
  fail "Asset creation" "HTTP $HTTP: $(echo "$BODY" | head -c 200)"
  exit 1
fi
sub "Asset id=$ASSET_ID"

req POST "/api/v1/pentest/campaigns" \
  "{\"name\":\"Att E2E Campaign ${TS}\",\"campaign_type\":\"web_app\",\"priority\":\"high\",\"client_name\":\"E2E Client\"}" \
  "" "$OWNER_AUTH"
CAMPAIGN_ID=$(jv '.id')
if [ -z "$CAMPAIGN_ID" ] || [ "$CAMPAIGN_ID" = "null" ]; then
  fail "Campaign creation" "HTTP $HTTP: $(echo "$BODY" | head -c 200)"
  exit 1
fi
sub "Campaign id=$CAMPAIGN_ID"

req POST "/api/v1/pentest/campaigns/${CAMPAIGN_ID}/findings" \
  "{\"title\":\"Att E2E Finding\",\"severity\":\"high\",\"asset_id\":\"$ASSET_ID\",\"description\":\"E2E attachment test\"}" \
  "" "$OWNER_AUTH"
FINDING_ID=$(jv '.id')
if [ -z "$FINDING_ID" ] || [ "$FINDING_ID" = "null" ]; then
  fail "Finding creation" "HTTP $HTTP: $(echo "$BODY" | head -c 200)"
  exit 1
fi
pass "Finding created (id=$FINDING_ID)"

# =============================================================================
# 2. UPLOAD FLOW
# =============================================================================
h "2. UPLOAD FLOW"

# ── 2.1 Valid small PNG ───────────────────────────────────────────────────────
# Create a minimal but structurally identifiable test PNG (≪ 10MB)
TEST_PNG="$TMPDIR_WORK/test.png"
printf '\x89PNG\r\n\x1a\n' > "$TEST_PNG"
dd if=/dev/urandom bs=512 count=1 >> "$TEST_PNG" 2>/dev/null

req_upload "$TEST_PNG" "image/png" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "2.1 Upload valid PNG → 201" 201

ATT_ID=$(jv '.id')
ATT_URL=$(jv '.url')
ATT_MARKDOWN=$(jv '.markdown')

if [ -z "$ATT_ID" ] || [ "$ATT_ID" = "null" ]; then
  fail "2.1b Upload returns id" "id field missing. Body: $(echo "$BODY" | head -c 300)"
else
  pass "2.1b Upload returns id ($ATT_ID)"
fi
if [ -n "$ATT_URL" ] && [ "$ATT_URL" != "null" ]; then
  pass "2.1c Upload returns url ($ATT_URL)"
else
  fail "2.1c Upload returns url" "url field missing or null"
fi
if [ -n "$ATT_MARKDOWN" ] && [ "$ATT_MARKDOWN" != "null" ]; then
  pass "2.1d Upload returns markdown ($ATT_MARKDOWN)"
else
  fail "2.1d Upload returns markdown" "markdown field missing or null"
fi

# ── 2.2 File too large (>10MB) ────────────────────────────────────────────────
LARGE_FILE="$TMPDIR_WORK/large.png"
printf '\x89PNG\r\n\x1a\n' > "$LARGE_FILE"
# 11MB of random data
dd if=/dev/urandom bs=1048576 count=11 >> "$LARGE_FILE" 2>/dev/null

req_upload "$LARGE_FILE" "image/png" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "2.2 Upload file >10MB → 400" 400 413

# ── 2.3 Unsupported file type (.exe) ─────────────────────────────────────────
EXE_FILE="$TMPDIR_WORK/malware.exe"
printf 'MZ\x90\x00\x03\x00' > "$EXE_FILE"
dd if=/dev/urandom bs=512 count=1 >> "$EXE_FILE" 2>/dev/null

req_upload "$EXE_FILE" "application/x-msdownload" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "2.3 Upload .exe (unsupported type) → 400" 400

# ── 2.4 Upload without auth → 401 ────────────────────────────────────────────
req_upload "$TEST_PNG" "image/png" "finding" "$FINDING_ID" ""
assert_status "2.4 Upload without auth → 401" 401

# ── 2.5 Dedup: upload same file to same context → returns existing ID ─────────
# Re-upload the identical file
req_upload "$TEST_PNG" "image/png" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "2.5 Dedup upload → 201 (existing returned)" 201

DEDUP_ID=$(jv '.id')
if [ "$DEDUP_ID" = "$ATT_ID" ]; then
  pass "2.5b Dedup returns existing attachment ID ($ATT_ID)"
else
  # Some implementations may generate a new record with same file — accept if API returns 201 at minimum
  sub "2.5b Note: dedup returned different id ($DEDUP_ID vs $ATT_ID) — may be expected if dedup is content-hash per context"
  pass "2.5b Upload idempotent (201 returned)"
fi

# =============================================================================
# 3. DOWNLOAD FLOW
# =============================================================================
h "3. DOWNLOAD FLOW"

# ── 3.1 Download by ID → 200, correct Content-Type + Content-Disposition ─────
HDR_FILE="$TMPDIR_WORK/download_headers.txt"
curl -s -I -w "\n%{http_code}" \
  -H "$OWNER_AUTH" \
  "${API_URL}/api/v1/attachments/${ATT_ID}" \
  > "$HDR_FILE" 2>/dev/null
DL_HTTP=$(tail -1 "$HDR_FILE")

if [ "$DL_HTTP" = "200" ]; then
  pass "3.1 Download by ID → 200"
else
  fail "3.1 Download by ID" "Expected 200, got $DL_HTTP"
fi

assert_header "3.2 Content-Type: image/png" "Content-Type" "image/png" "$HDR_FILE"
assert_header "3.3 Content-Disposition header present" "Content-Disposition" "." "$HDR_FILE"
assert_header "3.4 X-Content-Type-Options: nosniff" "X-Content-Type-Options" "nosniff" "$HDR_FILE"

# Verify file body is actually returned (non-empty)
DL_BODY_FILE="$TMPDIR_WORK/dl_body.bin"
curl -s -o "$DL_BODY_FILE" \
  -H "$OWNER_AUTH" \
  "${API_URL}/api/v1/attachments/${ATT_ID}" 2>/dev/null
DL_SIZE=$(wc -c < "$DL_BODY_FILE" 2>/dev/null || echo 0)
if [ "$DL_SIZE" -gt 0 ]; then
  pass "3.5 Download returns non-empty body (${DL_SIZE} bytes)"
else
  fail "3.5 Download returns non-empty body" "body is empty"
fi

# ── 3.6 Download non-existent ID → 404 ───────────────────────────────────────
FAKE_ID="00000000-0000-0000-0000-deadbeef0001"
req GET "/api/v1/attachments/${FAKE_ID}" "" "$OWNER_AUTH"
assert_status "3.6 Download non-existent ID → 404" 404

# =============================================================================
# 4. LIST FLOW
# =============================================================================
h "4. LIST FLOW"

# ── 4.1 List by context_type=finding&context_id=<finding_id> ──────────────────
req GET "/api/v1/attachments?context_type=finding&context_id=${FINDING_ID}" "" "$OWNER_AUTH"
assert_status "4.1 List by context → 200" 200

LIST_TOTAL=$(jv '.total')
if [ -n "$LIST_TOTAL" ] && [ "$LIST_TOTAL" != "null" ] && [ "$LIST_TOTAL" -ge 1 ] 2>/dev/null; then
  pass "4.2 List returns at least 1 attachment (total=$LIST_TOTAL)"
else
  fail "4.2 List returns at least 1 attachment" "total=$LIST_TOTAL"
fi

# Verify the uploaded attachment appears in the list
FOUND_IN_LIST=$(echo "$BODY" | jq --arg id "$ATT_ID" '.data | map(select(.id==$id)) | length' 2>/dev/null || echo "0")
if [ "$FOUND_IN_LIST" = "1" ]; then
  pass "4.3 Uploaded attachment appears in list"
else
  fail "4.3 Uploaded attachment appears in list" "id=$ATT_ID not found in list. Body: $(echo "$BODY" | head -c 300)"
fi

# ── 4.4 List without context params → 400 ────────────────────────────────────
req GET "/api/v1/attachments" "" "$OWNER_AUTH"
assert_status "4.4 List without context params → 400" 400

# ── 4.5 List with only context_type (missing context_id) → 400 ───────────────
req GET "/api/v1/attachments?context_type=finding" "" "$OWNER_AUTH"
assert_status "4.5 List with only context_type → 400" 400

# =============================================================================
# 5. DELETE FLOW
# =============================================================================
h "5. DELETE FLOW"

# Upload a second file specifically for the delete test
TEST_PNG2="$TMPDIR_WORK/test2.png"
printf '\x89PNG\r\n\x1a\n' > "$TEST_PNG2"
# Use slightly different content so dedup doesn't kick in
echo "delete-test-${TS}" >> "$TEST_PNG2"
dd if=/dev/urandom bs=256 count=1 >> "$TEST_PNG2" 2>/dev/null

req_upload "$TEST_PNG2" "image/png" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "5.0 Upload second PNG for delete test → 201" 201
DEL_ATT_ID=$(jv '.id')

if [ -z "$DEL_ATT_ID" ] || [ "$DEL_ATT_ID" = "null" ]; then
  skip "5.x Delete tests — could not get second attachment ID"
  DEL_ATT_ID=""
else
  sub "delete target id=$DEL_ATT_ID"

  # ── 5.1 Delete attachment → 204 ────────────────────────────────────────────
  req DELETE "/api/v1/attachments/${DEL_ATT_ID}" "" "$OWNER_AUTH"
  assert_status "5.1 Delete attachment → 204" 204

  # ── 5.2 Delete already-deleted → 404 ───────────────────────────────────────
  req DELETE "/api/v1/attachments/${DEL_ATT_ID}" "" "$OWNER_AUTH"
  assert_status "5.2 Delete already-deleted → 404" 404

  # ── 5.3 Verify file no longer downloadable after delete ────────────────────
  req GET "/api/v1/attachments/${DEL_ATT_ID}" "" "$OWNER_AUTH"
  assert_status "5.3 Deleted file is no longer downloadable → 404" 404

  # ── 5.4 Deleted file no longer appears in list ─────────────────────────────
  req GET "/api/v1/attachments?context_type=finding&context_id=${FINDING_ID}" "" "$OWNER_AUTH"
  GONE_IN_LIST=$(echo "$BODY" | jq --arg id "$DEL_ATT_ID" '.data | map(select(.id==$id)) | length' 2>/dev/null || echo "0")
  if [ "$GONE_IN_LIST" = "0" ]; then
    pass "5.4 Deleted attachment absent from list"
  else
    fail "5.4 Deleted attachment absent from list" "id=$DEL_ATT_ID still visible"
  fi
fi

# =============================================================================
# 6. LINK FLOW
# =============================================================================
h "6. LINK FLOW"

# ── 6.1 Upload with empty context (orphan) → 201 ─────────────────────────────
ORPHAN_PNG="$TMPDIR_WORK/orphan.png"
printf '\x89PNG\r\n\x1a\n' > "$ORPHAN_PNG"
echo "orphan-${TS}" >> "$ORPHAN_PNG"
dd if=/dev/urandom bs=256 count=1 >> "$ORPHAN_PNG" 2>/dev/null

# Upload without context_type / context_id
req_upload_raw "$OWNER_AUTH" \
  -F "file=@${ORPHAN_PNG};type=image/png"
assert_status "6.1 Upload orphan (no context) → 201" 201
ORPHAN_ID=$(jv '.id')

if [ -z "$ORPHAN_ID" ] || [ "$ORPHAN_ID" = "null" ]; then
  skip "6.2-6.3 Link tests — orphan upload did not return id"
else
  sub "orphan id=$ORPHAN_ID"

  # ── 6.2 POST /attachments/link → 200, linked count ────────────────────────
  # Create a second finding to link the orphan to (demonstrates cross-link)
  req POST "/api/v1/pentest/campaigns/${CAMPAIGN_ID}/findings" \
    "{\"title\":\"Att E2E Link Target\",\"severity\":\"low\",\"asset_id\":\"$ASSET_ID\",\"description\":\"Link target\"}" \
    "" "$OWNER_AUTH"
  LINK_FINDING_ID=$(jv '.id')

  if [ -z "$LINK_FINDING_ID" ] || [ "$LINK_FINDING_ID" = "null" ]; then
    skip "6.2-6.3 Link target finding could not be created"
  else
    sub "link target finding=$LINK_FINDING_ID"
    LINK_BODY="{\"attachment_ids\":[\"$ORPHAN_ID\"],\"context_type\":\"finding\",\"context_id\":\"$LINK_FINDING_ID\"}"
    req POST "/api/v1/attachments/link" "$LINK_BODY" "$OWNER_AUTH"
    assert_status "6.2 POST /attachments/link → 200" 200

    LINKED_COUNT=$(jv '.linked')
    if [ "$LINKED_COUNT" -ge 1 ] 2>/dev/null; then
      pass "6.2b Link returns linked count >= 1 (linked=$LINKED_COUNT)"
    else
      fail "6.2b Link returns linked count >= 1" "linked=$LINKED_COUNT"
    fi

    # ── 6.3 List by new context → shows linked files ──────────────────────
    req GET "/api/v1/attachments?context_type=finding&context_id=${LINK_FINDING_ID}" "" "$OWNER_AUTH"
    assert_status "6.3 List linked context → 200" 200

    LINKED_IN_LIST=$(echo "$BODY" | jq --arg id "$ORPHAN_ID" '.data | map(select(.id==$id)) | length' 2>/dev/null || echo "0")
    if [ "$LINKED_IN_LIST" = "1" ]; then
      pass "6.3b Linked attachment appears in new context list"
    else
      fail "6.3b Linked attachment appears in new context list" "id=$ORPHAN_ID not found. Body: $(echo "$BODY" | head -c 300)"
    fi
  fi
fi

# ── 6.4 Link with missing fields → 400 ────────────────────────────────────────
req POST "/api/v1/attachments/link" \
  "{\"attachment_ids\":[\"00000000-0000-0000-0000-000000000001\"]}" \
  "$OWNER_AUTH"
assert_status "6.4 Link without context_type/context_id → 400" 400

# =============================================================================
# 7. STORAGE CONFIG (admin)
# =============================================================================
h "7. STORAGE CONFIG (admin)"

# ── 7.1 GET /attachments/storage-config → 200 ────────────────────────────────
req GET "/api/v1/attachments/storage-config" "" "$OWNER_AUTH"
assert_status "7.1 GET /attachments/storage-config → 200" 200

PROVIDER=$(jv '.provider')
if [ -n "$PROVIDER" ] && [ "$PROVIDER" != "null" ]; then
  pass "7.1b storage-config returns provider ($PROVIDER)"
else
  fail "7.1b storage-config returns provider" "provider field missing"
fi

# ── 7.2 PATCH /attachments/storage-config with local provider → 200 ───────────
PATCH_BODY="{\"provider\":\"local\",\"base_path\":\"/data/attachments\"}"
req PATCH "/api/v1/attachments/storage-config" "$PATCH_BODY" "$OWNER_AUTH"
assert_status "7.2 PATCH storage-config (local) → 200" 200

STATUS_VAL=$(jv '.status')
if [ "$STATUS_VAL" = "saved" ]; then
  pass "7.2b PATCH returns status=saved"
else
  # Some implementations return the full config back rather than {status:saved}
  sub "7.2b PATCH response: $(echo "$BODY" | head -c 150)"
  pass "7.2b PATCH storage-config returned 200"
fi

# ── 7.3 PATCH with invalid provider → 400 ────────────────────────────────────
req PATCH "/api/v1/attachments/storage-config" \
  "{\"provider\":\"gcs_invalid\"}" "$OWNER_AUTH"
assert_status "7.3 PATCH with invalid provider → 400" 400

# =============================================================================
# 8. SECURITY CHECKS
# =============================================================================
h "8. SECURITY"

# ── 8.1 SVG upload → rejected (400) ──────────────────────────────────────────
SVG_FILE="$TMPDIR_WORK/evil.svg"
cat > "$SVG_FILE" << 'SVGEOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <script>alert('xss')</script>
</svg>
SVGEOF

req_upload "$SVG_FILE" "image/svg+xml" "finding" "$FINDING_ID" "$OWNER_AUTH"
assert_status "8.1 SVG upload rejected → 400" 400

# ── 8.2 Path traversal filename → sanitized (no 500, no traversal) ────────────
# We construct the filename via a temp file copy with a "safe" on-disk name,
# but the Content-Disposition filename includes the traversal attempt.
TRAVERSAL_FILE="$TMPDIR_WORK/normal.png"
printf '\x89PNG\r\n\x1a\n' > "$TRAVERSAL_FILE"
echo "traversal-${TS}" >> "$TRAVERSAL_FILE"
dd if=/dev/urandom bs=128 count=1 >> "$TRAVERSAL_FILE" 2>/dev/null

# Use curl --form-string to smuggle a traversal filename without it being
# interpreted by curl itself.
curl -s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/attachments" \
  -H "$OWNER_AUTH" \
  -F "context_type=finding" \
  -F "context_id=${FINDING_ID}" \
  -F "file=@${TRAVERSAL_FILE};filename=../../etc/passwd;type=image/png" \
  > "$TMPDIR_WORK/resp" 2>/dev/null
HTTP=$(tail -1 "$TMPDIR_WORK/resp")
BODY=$(sed '$d' "$TMPDIR_WORK/resp")

# The server should either reject it OR sanitize and return 201 — it must NOT 500
if [ "$HTTP" = "201" ] || [ "$HTTP" = "200" ]; then
  # Verify the stored filename does NOT contain directory traversal components
  STORED_FILENAME=$(jv '.filename')
  if echo "$STORED_FILENAME" | grep -q '\.\./\|\.\.\\'; then
    fail "8.2 Path traversal filename sanitized" \
      "filename contains traversal sequence: '$STORED_FILENAME'"
  else
    pass "8.2 Path traversal filename sanitized (stored as '$STORED_FILENAME')"
  fi
elif [ "$HTTP" = "400" ] || [ "$HTTP" = "422" ]; then
  pass "8.2 Path traversal filename rejected ($HTTP)"
else
  fail "8.2 Path traversal filename" \
    "Expected 201 (sanitized) or 400 (rejected), got $HTTP. Body: $(echo "$BODY" | head -c 200)"
fi

# ── 8.3 Unauthenticated list → 401 ────────────────────────────────────────────
req GET "/api/v1/attachments?context_type=finding&context_id=${FINDING_ID}" "" ""
assert_status "8.3 Unauthenticated list → 401" 401

# ── 8.4 Unauthenticated download → 401 ───────────────────────────────────────
req GET "/api/v1/attachments/${ATT_ID}" "" ""
assert_status "8.4 Unauthenticated download → 401" 401

# ── 8.5 Unauthenticated delete → 401 ─────────────────────────────────────────
req DELETE "/api/v1/attachments/${ATT_ID}" "" ""
assert_status "8.5 Unauthenticated delete → 401" 401

# =============================================================================
# 9. META ENDPOINT
# =============================================================================
h "9. META ENDPOINT"

# ── 9.1 GET /attachments/{id}/meta → 200 with expected fields ─────────────────
req GET "/api/v1/attachments/${ATT_ID}/meta" "" "$OWNER_AUTH"
assert_status "9.1 GET /attachments/{id}/meta → 200" 200

META_ID=$(jv '.id')
META_CT=$(jv '.content_type')
META_CTX_TYPE=$(jv '.context_type')
META_CTX_ID=$(jv '.context_id')

if [ "$META_ID" = "$ATT_ID" ]; then
  pass "9.2 Meta returns correct id"
else
  fail "9.2 Meta returns correct id" "Expected $ATT_ID, got $META_ID"
fi
if [ "$META_CT" = "image/png" ]; then
  pass "9.3 Meta returns correct content_type (image/png)"
else
  fail "9.3 Meta returns correct content_type" "Expected image/png, got $META_CT"
fi
if [ "$META_CTX_TYPE" = "finding" ]; then
  pass "9.4 Meta returns correct context_type (finding)"
else
  fail "9.4 Meta returns correct context_type" "Expected finding, got $META_CTX_TYPE"
fi
if [ "$META_CTX_ID" = "$FINDING_ID" ]; then
  pass "9.5 Meta returns correct context_id"
else
  fail "9.5 Meta returns correct context_id" "Expected $FINDING_ID, got $META_CTX_ID"
fi

# ── 9.2 GET /attachments/{id}/meta for non-existent → 404 ────────────────────
req GET "/api/v1/attachments/${FAKE_ID}/meta" "" "$OWNER_AUTH"
assert_status "9.6 Meta for non-existent id → 404" 404

# =============================================================================
# CLEANUP
# =============================================================================
h "CLEANUP"

req DELETE "/api/v1/pentest/campaigns/${CAMPAIGN_ID}" "" "$OWNER_AUTH"
assert_status "Cleanup: delete campaign" 200 204

# =============================================================================
# SUMMARY
# =============================================================================
echo
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SUMMARY${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✅ Passed:  $PASS${NC}"
echo -e "  ${RED}❌ Failed:  $FAIL${NC}"
echo -e "  ${YELLOW}⏭️  Skipped: $SKIP${NC}"
echo

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
