#!/usr/bin/env bash
# Obtiene un JWT de Keycloak para un usuario de demo
# Uso: ./scripts/get-token.sh alice alice123
#       ./scripts/get-token.sh bob bob123

set -euo pipefail

USER="${1:-alice}"
PASS="${2:-alice123}"
KC_URL="http://localhost:8080"
REALM="ai-platform"
CLIENT_ID="apisix"
CLIENT_SECRET="apisix-client-secret"

echo "==> Obteniendo token para usuario: $USER"

RESPONSE=$(curl -sf -X POST \
  "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USER}" \
  -d "password=${PASS}" \
  -d "scope=openid profile email")

ACCESS_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo ""
echo "TOKEN=$ACCESS_TOKEN"
echo ""
echo "Para usar:"
echo "  export TOKEN=$ACCESS_TOKEN"
echo "  curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:9080/api/conversations"
