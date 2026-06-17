package gateway_test

import rego.v1
import data.gateway

# ── Helpers ───────────────────────────────────────────────────────────────────
# Construye un JWT sin firma (igual de válido para io.jwt.decode, que no la verifica)
# con los claims indicados, para reproducir el input real que envía el plugin OPA de APISIX.
mock_token(claims) := sprintf("%s.%s.sig", [
  base64url.encode(json.marshal({"alg": "none", "typ": "JWT"})),
  base64url.encode(json.marshal(claims)),
])

mock_input(method, path, roles, tenant) := {
  "type": "http",
  "request": {
    "method": method,
    "path": path,
    "headers": {
      "authorization": sprintf("Bearer %s", [mock_token({
        "sub": "user-123",
        "tenant_id": tenant,
        "realm_roles": roles,
      })]),
    },
  },
}

# ── CASOS POSITIVOS ───────────────────────────────────────────────────────────
test_user_can_get_conversations if {
  gateway.allow with input as mock_input("GET", "/api/conversations", ["user"], "acme")
}

test_admin_can_delete_conversation if {
  gateway.allow with input as mock_input("DELETE", "/api/conversations", ["admin"], "acme")
}

test_agent_accionable_can_run if {
  gateway.allow with input as mock_input("POST", "/api/agents/run", ["agent:accionable"], "acme")
}

test_platform_admin_can_access_any_route if {
  gateway.allow with input as mock_input("DELETE", "/api/admin", ["platform_admin"], "platform")
}

# ── CASOS NEGATIVOS ───────────────────────────────────────────────────────────
test_user_cannot_delete_conversation if {
  not gateway.allow with input as mock_input("DELETE", "/api/conversations", ["user"], "acme")
}

test_user_cannot_run_agent if {
  not gateway.allow with input as mock_input("POST", "/api/agents/run", ["user"], "acme")
}

test_missing_tenant_denied if {
  not gateway.allow with input as mock_input("GET", "/api/conversations", ["user"], "")
}

# ── CROSS-TENANT ──────────────────────────────────────────────────────────────
# (La separación real de tenant se hace en fine-grained; aquí validamos que el claim existe)
test_different_tenant_with_valid_role_allowed_at_gateway if {
  # Gateway solo valida rol y presencia de tenant_id, no aislamiento entre tenants
  gateway.allow with input as mock_input("GET", "/api/conversations", ["user"], "globex")
}

# ── AGENTES CON ROL INCORRECTO ────────────────────────────────────────────────
test_informativo_agent_cannot_post_knowledge if {
  not gateway.allow with input as mock_input("POST", "/api/knowledge", ["agent:informativo"], "acme")
}

test_asesor_agent_can_read_knowledge if {
  gateway.allow with input as mock_input("GET", "/api/knowledge", ["agent:asesor"], "acme")
}
