#!/usr/bin/env bash
# Configura rutas y plugins en APISIX via Admin API
# Ejecutar después de que el stack esté levantado: ./scripts/init-apisix.sh

set -euo pipefail

APISIX_ADMIN="http://localhost:9092"
ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"
KC_URL="http://keycloak:8080"
KC_REALM="ai-platform"

H='-H "X-API-KEY: '"$ADMIN_KEY"'" -H "Content-Type: application/json"'
CURL="curl -sf -H X-API-KEY:${ADMIN_KEY} -H Content-Type:application/json"

echo "==> Esperando Admin API de APISIX..."
until $CURL "${APISIX_ADMIN}/apisix/admin/routes" > /dev/null 2>&1; do sleep 2; done
echo "    Admin API lista."

# ── Upstream: mock-backend ────────────────────────────────────────────────────
echo "==> Creando upstream mock-backend..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/upstreams/1" -d '{
  "id": "1",
  "name": "mock-backend",
  "type": "roundrobin",
  "nodes": { "mock-backend:80": 1 }
}'

# ── Upstream: orchestrator ────────────────────────────────────────────────────
echo "==> Creando upstream orchestrator..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/upstreams/2" -d '{
  "id": "2",
  "name": "orchestrator",
  "type": "roundrobin",
  "nodes": { "orchestrator:8000": 1 }
}'

# ── Plugin global: OIDC contra Keycloak ──────────────────────────────────────
# Se aplica en cada ruta individualmente para mayor control
OIDC_PLUGIN=$(cat <<JSON
{
  "client_id": "apisix",
  "client_secret": "apisix-client-secret",
  "discovery": "${KC_URL}/realms/${KC_REALM}/.well-known/openid-configuration",
  "introspection_endpoint": "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token/introspect",
  "scope": "openid profile email",
  "bearer_only": true,
  "realm": "${KC_REALM}",
  "introspection_endpoint_auth_method": "client_secret_post",
  "set_access_token_header": true,
  "access_token_in_authorization_header": true
}
JSON
)

# ── Plugin OPA configurado para el gateway ────────────────────────────────────
OPA_GATEWAY_PLUGIN=$(cat <<'JSON'
{
  "host": "http://opa:8181",
  "policy": "gateway",
  "timeout": 3000
}
JSON
)

# ── Ruta 1: /api/conversations ────────────────────────────────────────────────
echo "==> Creando ruta /api/conversations..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/routes/1" -d "$(cat <<JSON
{
  "id": "1",
  "name": "conversations",
  "uri": "/api/conversations*",
  "methods": ["GET", "POST", "DELETE"],
  "upstream_id": "1",
  "plugins": {
    "openid-connect": $OIDC_PLUGIN,
    "opa": $OPA_GATEWAY_PLUGIN
  }
}
JSON
)"

# ── Ruta 2: /api/agents/run ───────────────────────────────────────────────────
echo "==> Creando ruta /api/agents/run..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/routes/2" -d "$(cat <<JSON
{
  "id": "2",
  "name": "agents-run",
  "uri": "/api/agents/run",
  "methods": ["POST"],
  "upstream_id": "1",
  "plugins": {
    "openid-connect": $OIDC_PLUGIN,
    "opa": $OPA_GATEWAY_PLUGIN
  }
}
JSON
)"

# ── Ruta 3: /api/knowledge ────────────────────────────────────────────────────
echo "==> Creando ruta /api/knowledge..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/routes/3" -d "$(cat <<JSON
{
  "id": "3",
  "name": "knowledge",
  "uri": "/api/knowledge*",
  "methods": ["GET", "POST"],
  "upstream_id": "1",
  "plugins": {
    "openid-connect": $OIDC_PLUGIN,
    "opa": $OPA_GATEWAY_PLUGIN
  }
}
JSON
)"

# ── Ruta 4: /api/admin ────────────────────────────────────────────────────────
echo "==> Creando ruta /api/admin..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/routes/4" -d "$(cat <<JSON
{
  "id": "4",
  "name": "admin",
  "uri": "/api/admin*",
  "methods": ["GET", "POST", "PUT", "DELETE"],
  "upstream_id": "1",
  "plugins": {
    "openid-connect": $OIDC_PLUGIN,
    "opa": $OPA_GATEWAY_PLUGIN
  }
}
JSON
)"

# ── Ruta 5: /orchestrator/* (sin OPA de gateway, fine-grained interno) ────────
echo "==> Creando ruta /orchestrator/*..."
$CURL -X PUT "${APISIX_ADMIN}/apisix/admin/routes/5" -d "$(cat <<JSON
{
  "id": "5",
  "name": "orchestrator",
  "uri": "/orchestrator/*",
  "methods": ["GET", "POST"],
  "upstream_id": "2",
  "plugins": {
    "openid-connect": $OIDC_PLUGIN,
    "proxy-rewrite": {
      "regex_uri": ["/orchestrator/(.*)", "/\$1"]
    }
  }
}
JSON
)"

echo ""
echo "✓ APISIX configurado. Rutas disponibles:"
echo "  GET/POST/DELETE http://localhost:9080/api/conversations"
echo "  POST            http://localhost:9080/api/agents/run"
echo "  GET/POST        http://localhost:9080/api/knowledge"
echo "  GET/POST/PUT/DELETE http://localhost:9080/api/admin"
echo "  POST            http://localhost:9080/orchestrator/authorize/resource"
echo "  POST            http://localhost:9080/orchestrator/authorize/agent-action"
echo "  POST            http://localhost:9080/orchestrator/secrets/access"
