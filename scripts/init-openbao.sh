#!/usr/bin/env bash
# Inicializa OpenBao: habilita KV secrets engine y carga credenciales de demo
set -euo pipefail

BAO_ADDR="http://localhost:8200"
BAO_TOKEN="root-token"

C="curl -sf -H X-Vault-Token:${BAO_TOKEN} -H Content-Type:application/json ${BAO_ADDR}"

echo "==> Esperando OpenBao..."
until curl -sf "${BAO_ADDR}/v1/sys/health" > /dev/null 2>&1; do sleep 2; done

# Inicializar si es necesario
STATUS=$(curl -sf "${BAO_ADDR}/v1/sys/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('initialized','false'))" 2>/dev/null || echo "false")

if [ "$STATUS" != "True" ] && [ "$STATUS" != "true" ]; then
  echo "==> Inicializando OpenBao..."
  INIT=$(curl -sf -X POST "${BAO_ADDR}/v1/sys/init" \
    -H "Content-Type: application/json" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')
  UNSEAL_KEY=$(echo "$INIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['keys'][0])")
  ROOT_TOKEN=$(echo "$INIT"  | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
  echo "  Unseal key: $UNSEAL_KEY"
  echo "  Root token: $ROOT_TOKEN"
  echo "  IMPORTANTE: guarda estos valores. Para esta demo se usará el token de dev configurado."

  curl -sf -X POST "${BAO_ADDR}/v1/sys/unseal" \
    -H "Content-Type: application/json" \
    -d "{\"key\": \"$UNSEAL_KEY\"}" > /dev/null
fi

echo "==> Habilitando KV secrets engine v2..."
curl -sf -X POST "${BAO_ADDR}/v1/sys/mounts/secret" \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"type": "kv", "options": {"version": "2"}}' 2>/dev/null || echo "  (ya habilitado)"

echo "==> Cargando credenciales delegadas de demo..."

# Credenciales de Jira para agent-acme-001 (en nombre de alice)
curl -sf -X POST "${BAO_ADDR}/v1/secret/data/agents/agent-acme-001/credentials/jira" \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "url":      "https://acme.atlassian.net",
      "username": "alice@acme.com",
      "api_token": "jira-demo-token-alice-001",
      "on_behalf_of": "alice"
    }
  }'
echo "  ✓ agents/agent-acme-001/credentials/jira"

# Credenciales de PagerDuty para agent-acme-001
curl -sf -X POST "${BAO_ADDR}/v1/secret/data/agents/agent-acme-001/credentials/pagerduty" \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "api_key":     "pd-demo-api-key-alice",
      "service_id":  "P123456",
      "on_behalf_of": "alice"
    }
  }'
echo "  ✓ agents/agent-acme-001/credentials/pagerduty"

# Credenciales de Confluence para agent-acme-002 (asesor)
curl -sf -X POST "${BAO_ADDR}/v1/secret/data/agents/agent-acme-002/credentials/confluence" \
  -H "X-Vault-Token: ${BAO_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "url":      "https://acme.atlassian.net/wiki",
      "username": "alice@acme.com",
      "api_token": "confluence-demo-token-alice-002",
      "on_behalf_of": "alice"
    }
  }'
echo "  ✓ agents/agent-acme-002/credentials/confluence"

echo ""
echo "✓ OpenBao inicializado. UI disponible en http://localhost:8200/ui"
echo "  Token: root-token"
