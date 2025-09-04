#!/usr/bin/env bash
set -euo pipefail

# Simple integration checks for JWT role mapping
# Requires demo stack running via docker compose

PGFS_BASE=${PGFS_BASE:-http://localhost:9000}
KC_BASE=${KC_BASE:-http://localhost:8081}
REALM=${REALM:-demo}

echo "[wait] Waiting for Keycloak well-known..."
for i in {1..60}; do
  if curl -fsS "$KC_BASE/realms/$REALM/.well-known/openid-configuration" > /dev/null; then
    break
  fi
  sleep 1
  if [[ $i -eq 60 ]]; then
    echo "Keycloak not ready" >&2
    exit 1
  fi
done

echo "[wait] Waiting for pg_featureserv..."
for i in {1..60}; do
  if curl -fsS "$PGFS_BASE/api.json" > /dev/null; then
    break
  fi
  sleep 1
  if [[ $i -eq 60 ]]; then
    echo "pg_featureserv not ready" >&2
    exit 1
  fi
done

get_token() {
  local client_id=$1
  local secret=$2
  local token_endpoint="$KC_BASE/realms/$REALM/protocol/openid-connect/token"
  local resp
  resp=$(curl -fsS -X POST "$token_endpoint" \
    -d grant_type=client_credentials \
    -d client_id="$client_id" \
    -d client_secret="$secret")
  # Prefer jq if available
  if command -v jq >/dev/null 2>&1; then
    echo "$resp" | jq -r .access_token
    return 0
  fi
  # Fallback to python
  if command -v python3 >/dev/null 2>&1; then
    python3 - << 'PY'
import sys, json
print(json.load(sys.stdin)["access_token"])
PY
    return 0
  fi
  echo "Please install 'jq' or 'python3' to parse tokens" >&2
  return 1
}

http_code() {
  local url=$1
  local auth=${2:-}
  if [[ -n "$auth" ]]; then
    curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $auth" "$url"
  else
    curl -s -o /dev/null -w "%{http_code}" "$url"
  fi
}

expect_status() {
  local want=$1
  local url=$2
  local token=${3:-}
  local code
  code=$(http_code "$url" "$token")
  if [[ "$code" != "$want" ]]; then
    echo "FAIL: $url expected $want got $code" >&2
    exit 1
  fi
  echo "OK  : $url ($code)"
}

expect_not_status() {
  local notwant=$1
  local url=$2
  local token=${3:-}
  local code
  code=$(http_code "$url" "$token")
  if [[ "$code" == "$notwant" ]]; then
    echo "FAIL: $url expected != $notwant got $code" >&2
    exit 1
  fi
  echo "OK  : $url (!= $notwant, got $code)"
}

echo "[anon] Testing as anonymous (role=anon)"
expect_status 200 "$PGFS_BASE/collections/public.cities_view/items?limit=1"
expect_not_status 200 "$PGFS_BASE/collections/public.cities/items?limit=1"
expect_status 200 "$PGFS_BASE/functions/postgisftw.buffer/items?dist=1"
expect_not_status 200 "$PGFS_BASE/functions/postgisftw.geo_grid/items?num_x=2&num_y=2"

echo "[token] Fetching reader token..."
READER_TOKEN=$(get_token pgfs-reader reader-secret)

echo "[reader] Testing with reader token"
expect_status 200 "$PGFS_BASE/collections/public.cities/items?limit=1" "$READER_TOKEN"
expect_status 200 "$PGFS_BASE/functions/postgisftw.geo_grid/items?num_x=2&num_y=2" "$READER_TOKEN"

echo "[token] Fetching power token..."
POWER_TOKEN=$(get_token pgfs-power power-secret)

echo "[power] Testing with power token"
expect_status 200 "$PGFS_BASE/collections/public.cities/items?limit=1" "$POWER_TOKEN"
expect_status 200 "$PGFS_BASE/functions/postgisftw.geo_grid/items?num_x=2&num_y=2" "$POWER_TOKEN"

echo "All auth tests passed."

