#!/usr/bin/env bash
# FlowScript Cloud — Full Integration Test
# Requires: wrangler dev running on localhost:8787 with local D1
#
# Tests the complete pipeline:
#   1. Health check
#   2. Org creation + API key
#   3. Event ingestion (genesis + batch) with chain verification
#   4. Event retrieval
#   5. Witness attestation
#   6. Namespace stats
#   7. Chain break detection
#   8. Key management (create, list, revoke)
#   9. RBAC enforcement

set -euo pipefail

BASE="http://localhost:8787"
PASS=0
FAIL=0
TOTAL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert_status() {
  local desc="$1" expected="$2" actual="$3"
  TOTAL=$((TOTAL + 1))
  if [ "$expected" = "$actual" ]; then
    echo -e "${GREEN}PASS${NC} [$TOTAL] $desc (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC} [$TOTAL] $desc — expected HTTP $expected, got $actual"
    FAIL=$((FAIL + 1))
  fi
}

assert_contains() {
  local desc="$1" body="$2" pattern="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$body" | grep -q "$pattern"; then
    echo -e "${GREEN}PASS${NC} [$TOTAL] $desc"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC} [$TOTAL] $desc — body does not contain '$pattern'"
    echo "  Body: $body"
    FAIL=$((FAIL + 1))
  fi
}

assert_json_field() {
  local desc="$1" body="$2" field="$3" expected="$4"
  TOTAL=$((TOTAL + 1))
  # Use python3 for reliable JSON parsing
  local actual
  actual=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d$field)" 2>/dev/null || echo "PARSE_ERROR")
  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC} [$TOTAL] $desc ($actual)"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}FAIL${NC} [$TOTAL] $desc — expected '$expected', got '$actual'"
    FAIL=$((FAIL + 1))
  fi
}

echo "============================================="
echo " FlowScript Cloud — Integration Test Suite"
echo "============================================="
echo ""

# ─────────────────────────────────────────────────
# 1. HEALTH CHECK
# ─────────────────────────────────────────────────
echo -e "${YELLOW}--- 1. Health Check ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/health")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET /v1/health returns 200" 200 "$STATUS"
assert_json_field "Health status is ok" "$BODY" "['status']" "ok"

# ─────────────────────────────────────────────────
# 2. ORG CREATION
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 2. Organization Signup ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/orgs" \
  -H "Content-Type: application/json" \
  -d '{"name": "Integration Test Org", "slug": "integration-test"}')
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "POST /v1/orgs returns 201" 201 "$STATUS"
assert_contains "Response has api_key" "$BODY" "api_key"
assert_contains "Response has key with fsk_ prefix" "$BODY" "fsk_"

# Extract the API key and org slug
API_KEY=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
ORG_SLUG=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['org']['slug'])")
echo "  API Key: ${API_KEY:0:12}..."
echo "  Org Slug: $ORG_SLUG"

# Duplicate slug should fail
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/orgs" \
  -H "Content-Type: application/json" \
  -d '{"name": "Duplicate", "slug": "integration-test"}')
STATUS=$(echo "$RESP" | tail -1)
assert_status "Duplicate slug returns 409" 409 "$STATUS"

# Invalid slug
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/orgs" \
  -H "Content-Type: application/json" \
  -d '{"name": "Bad", "slug": "ab"}')
STATUS=$(echo "$RESP" | tail -1)
assert_status "Short slug returns 400" 400 "$STATUS"

# ─────────────────────────────────────────────────
# 3. AUTH ENFORCEMENT
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 3. Auth Enforcement ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/test/agent/events")
STATUS=$(echo "$RESP" | tail -1)
assert_status "GET without auth returns 401" 401 "$STATUS"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/test/agent/events" \
  -H "Authorization: Bearer fsk_0000000000000000000000000000000000000000000000000000000000000000")
STATUS=$(echo "$RESP" | tail -1)
assert_status "GET with bad key returns 401" 401 "$STATUS"

# ─────────────────────────────────────────────────
# 4. EVENT INGESTION — GENESIS
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 4. Event Ingestion (Genesis) ---${NC}"

# Build genesis event as a canonical JSON string.
# This must match Python's json.dumps(sort_keys=True, separators=(",",":"))
# Key order: adapter, data, event, prev_hash, seq, session_id, timestamp, v
GENESIS_EVENT='{"adapter":null,"data":{"content":"Test content 0","node_id":"node_0"},"event":"node_create","prev_hash":"sha256:GENESIS","seq":0,"session_id":"sess_test","timestamp":"2026-03-28T10:00:00+00:00","v":1}'

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/events" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{\"namespace\": \"$ORG_SLUG/test-agent\", \"events\": [\"$(echo "$GENESIS_EVENT" | sed 's/"/\\"/g')\"]}")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

echo "  Response: $BODY"
assert_status "POST /v1/events genesis returns 200" 200 "$STATUS"
assert_json_field "Accepted 1 event" "$BODY" "['accepted']" "1"
assert_contains "Response has witness" "$BODY" "witness"

# Capture the genesis hash from the witness
GENESIS_HASH_RESULT=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['witness']['chain_head_hash'])")
echo "  Genesis chain head hash: ${GENESIS_HASH_RESULT:0:20}..."

# Compare with expected hash from fixture
EXPECTED_GENESIS_HASH="sha256:84b43743811e2ae6f155af85002f9d06244687af15a4cedef9b87f5597600550"
TOTAL=$((TOTAL + 1))
if [ "$GENESIS_HASH_RESULT" = "$EXPECTED_GENESIS_HASH" ]; then
  echo -e "${GREEN}PASS${NC} [$TOTAL] Genesis hash matches fixture (cross-language verification!)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC} [$TOTAL] Genesis hash mismatch!"
  echo "  Expected: $EXPECTED_GENESIS_HASH"
  echo "  Got:      $GENESIS_HASH_RESULT"
  FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────
# 5. EVENT INGESTION — BATCH (seq 1-4)
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 5. Event Ingestion (Batch seq 1-4) ---${NC}"

# Build events 1-4 as canonical JSON strings
EVENT_1='{"adapter":null,"data":{"content":"Test content 1","node_id":"node_1"},"event":"node_create","prev_hash":"sha256:84b43743811e2ae6f155af85002f9d06244687af15a4cedef9b87f5597600550","seq":1,"session_id":"sess_test","timestamp":"2026-03-28T10:01:00+00:00","v":1}'
EVENT_2='{"adapter":null,"data":{"content":"Test content 2","node_id":"node_2"},"event":"node_create","prev_hash":"sha256:d90ec3fa8a2cbcc78ea356381ad7694e10b87912ad1cc9868645ba93048fd049","seq":2,"session_id":"sess_test","timestamp":"2026-03-28T10:02:00+00:00","v":1}'
EVENT_3='{"adapter":null,"data":{"content":"Test content 3","node_id":"node_3"},"event":"session_wrap","prev_hash":"sha256:caca4838ae4ca08a53666971b1ca9845eac012340728ec6dc52a108a8ace6200","seq":3,"session_id":"sess_test","timestamp":"2026-03-28T10:03:00+00:00","v":1}'
EVENT_4='{"adapter":null,"data":{"content":"Test content 4","node_id":"node_4"},"event":"session_wrap","prev_hash":"sha256:05aca65ab70f207072f71d1485f9f838590c291d49b8cd3f2967e425bd2eb1ad","seq":4,"session_id":"sess_test","timestamp":"2026-03-28T10:04:00+00:00","v":1}'

# Build the JSON body with escaped strings using python3 for correctness
BATCH_BODY=$(python3 -c "
import json
events = [
    '$EVENT_1',
    '$EVENT_2',
    '$EVENT_3',
    '$EVENT_4',
]
print(json.dumps({'namespace': '$ORG_SLUG/test-agent', 'events': events}))
")

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/events" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "$BATCH_BODY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

echo "  Response: $BODY"
assert_status "POST /v1/events batch returns 200" 200 "$STATUS"
assert_json_field "Accepted 4 events" "$BODY" "['accepted']" "4"

# Capture final chain head hash
FINAL_HASH=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['witness']['chain_head_hash'])")
EXPECTED_FINAL_HASH="sha256:99b0e0c9db4f17ecef012b5d77404c650bac454528a0e5f293b0910dac94e66a"
TOTAL=$((TOTAL + 1))
if [ "$FINAL_HASH" = "$EXPECTED_FINAL_HASH" ]; then
  echo -e "${GREEN}PASS${NC} [$TOTAL] Final chain hash matches fixture after batch (5-event chain verified!)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC} [$TOTAL] Final chain hash mismatch!"
  echo "  Expected: $EXPECTED_FINAL_HASH"
  echo "  Got:      $FINAL_HASH"
  FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────
# 6. EVENT RETRIEVAL
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 6. Event Retrieval ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/events" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET events returns 200" 200 "$STATUS"
assert_json_field "Total events is 5" "$BODY" "['total']" "5"

# Check event type filtering
RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/events?event_type=session_wrap" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET events with type filter returns 200" 200 "$STATUS"
assert_json_field "Filtered to session_wrap events (2)" "$BODY" "['total']" "2"

# Check session_id filtering
RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/events?session_id=sess_test" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET events with session filter returns 200" 200 "$STATUS"
assert_json_field "Session filter returns all 5" "$BODY" "['total']" "5"

# ─────────────────────────────────────────────────
# 7. WITNESS ATTESTATION
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 7. Witness Attestation ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/witnesses" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET witnesses returns 200" 200 "$STATUS"

WITNESS_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['witnesses']))")
TOTAL=$((TOTAL + 1))
if [ "$WITNESS_COUNT" -ge 2 ]; then
  echo -e "${GREEN}PASS${NC} [$TOTAL] At least 2 witnesses created (genesis + batch)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC} [$TOTAL] Expected >=2 witnesses, got $WITNESS_COUNT"
  FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────
# 8. NAMESPACE STATS
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 8. Namespace Stats ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/stats" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "GET stats returns 200" 200 "$STATUS"
assert_json_field "Namespace matches" "$BODY" "['namespace']" "$ORG_SLUG/test-agent"

# ─────────────────────────────────────────────────
# 9. CHAIN BREAK DETECTION
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 9. Chain Break Detection ---${NC}"

# Send event with wrong prev_hash
BAD_EVENT='{"adapter":null,"data":{"content":"Bad event"},"event":"node_create","prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","seq":5,"session_id":"sess_bad","timestamp":"2026-03-28T11:00:00+00:00","v":1}'

BAD_BODY=$(python3 -c "
import json
print(json.dumps({'namespace': '$ORG_SLUG/test-agent', 'events': ['$BAD_EVENT']}))
")

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/events" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "$BAD_BODY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

echo "  Response: $BODY"
assert_status "POST with bad prev_hash returns 409" 409 "$STATUS"
assert_contains "Error is chain_break" "$BODY" "chain_break"

# Send duplicate genesis (should fail)
DUP_GENESIS_BODY=$(python3 -c "
import json
print(json.dumps({'namespace': '$ORG_SLUG/test-agent', 'events': ['$GENESIS_EVENT']}))
")

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/events" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "$DUP_GENESIS_BODY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "Duplicate genesis returns 409" 409 "$STATUS"
assert_contains "Duplicate genesis detected" "$BODY" "GENESIS event received but namespace already has events"

# ─────────────────────────────────────────────────
# 10. KEY MANAGEMENT
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 10. Key Management ---${NC}"

# Create a viewer key
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/auth/keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{\"role\": \"viewer\", \"scope_type\": \"org\", \"scope_id\": \"$(echo "$BODY" | python3 -c "import sys; print('dummy')" 2>/dev/null || echo "dummy")\", \"label\": \"Test viewer\"}")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

# Need to get the actual org_id for scope_id
ORG_ID=$(curl -s "$BASE/v1/orgs/$ORG_SLUG" \
  -H "Authorization: Bearer $API_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['org']['id'])")

RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/auth/keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{\"role\": \"viewer\", \"scope_type\": \"org\", \"scope_id\": \"$ORG_ID\", \"label\": \"Test viewer key\"}")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "Create viewer key returns 201" 201 "$STATUS"
assert_contains "Viewer key has fsk_ prefix" "$BODY" "fsk_"

VIEWER_KEY=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
VIEWER_KEY_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['key_id'])")
echo "  Viewer key: ${VIEWER_KEY:0:12}..."

# Viewer should be able to read events
RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/events" \
  -H "Authorization: Bearer $VIEWER_KEY")
STATUS=$(echo "$RESP" | tail -1)
assert_status "Viewer can read events" 200 "$STATUS"

# Viewer should NOT be able to write events
VIEWER_WRITE_BODY=$(python3 -c "
import json
print(json.dumps({'namespace': '$ORG_SLUG/viewer-agent', 'events': ['$GENESIS_EVENT']}))
")
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/v1/events" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $VIEWER_KEY" \
  -d "$VIEWER_WRITE_BODY")
STATUS=$(echo "$RESP" | tail -1)
assert_status "Viewer cannot write events (403)" 403 "$STATUS"

# List keys
RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/auth/keys" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "List keys returns 200" 200 "$STATUS"
KEY_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['keys']))")
TOTAL=$((TOTAL + 1))
if [ "$KEY_COUNT" -ge 2 ]; then
  echo -e "${GREEN}PASS${NC} [$TOTAL] At least 2 keys listed (admin + viewer)"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${NC} [$TOTAL] Expected >=2 keys, got $KEY_COUNT"
  FAIL=$((FAIL + 1))
fi

# Revoke viewer key
RESP=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE/v1/auth/keys/$VIEWER_KEY_ID" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "Revoke key returns 200" 200 "$STATUS"
assert_contains "Key revoked" "$BODY" "revoked"

# Revoked key should fail auth
RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/test-agent/events" \
  -H "Authorization: Bearer $VIEWER_KEY")
STATUS=$(echo "$RESP" | tail -1)
assert_status "Revoked key returns 401" 401 "$STATUS"

# ─────────────────────────────────────────────────
# 11. NAMESPACE LISTING
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 11. Namespace Listing ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/orgs/$ORG_SLUG/namespaces" \
  -H "Authorization: Bearer $API_KEY")
BODY=$(echo "$RESP" | head -1)
STATUS=$(echo "$RESP" | tail -1)

assert_status "List namespaces returns 200" 200 "$STATUS"
assert_contains "Has test-agent namespace" "$BODY" "test-agent"

# ─────────────────────────────────────────────────
# 12. 404 HANDLING
# ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}--- 12. 404 Handling ---${NC}"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/nonexistent" \
  -H "Authorization: Bearer $API_KEY")
STATUS=$(echo "$RESP" | tail -1)
assert_status "Unknown route returns 404" 404 "$STATUS"

RESP=$(curl -s -w "\n%{http_code}" "$BASE/v1/namespaces/$ORG_SLUG/nonexistent-agent/events" \
  -H "Authorization: Bearer $API_KEY")
STATUS=$(echo "$RESP" | tail -1)
assert_status "Nonexistent namespace returns 404" 404 "$STATUS"

# ─────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────
echo ""
echo "============================================="
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, $TOTAL total"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
