# Política coarse-grained ejecutada por el plugin OPA de APISIX.
# El plugin envía: { "type": "http", "request": { "method", "path", "headers", ... }, "var": {...} }
# El JWT llega en input.request.headers.authorization como "Bearer <token>".
# Output esperado: { "allow": true/false, "reason": "..." }
package gateway

import rego.v1

# ── Tabla de permisos: ruta → métodos → roles permitidos ──────────────────────
route_permissions := {
  "/api/conversations": {
    "GET":    {"user", "admin", "platform_admin"},
    "POST":   {"user", "admin", "platform_admin"},
    "DELETE": {"admin", "platform_admin"}
  },
  "/api/agents/run": {
    "POST": {"agent:informativo", "agent:asesor", "agent:accionable"}
  },
  "/api/knowledge": {
    "GET":  {"user", "admin", "platform_admin", "agent:informativo", "agent:asesor", "agent:accionable"},
    "POST": {"admin", "platform_admin"}
  },
  "/api/admin": {
    "GET":    {"admin", "platform_admin"},
    "POST":   {"admin", "platform_admin"},
    "PUT":    {"admin", "platform_admin"},
    "DELETE": {"platform_admin"}
  }
}

# ── Extrae claims del JWT en el header Authorization ──────────────────────────
# io.jwt.decode no verifica firma — el token ya fue validado por APISIX/Keycloak.
_claims := payload if {
  auth := input.request.headers.authorization
  startswith(auth, "Bearer ")
  tok := substring(auth, 7, -1)
  [_, payload, _] := io.jwt.decode(tok)
}

# ── Regla principal ────────────────────────────────────────────────────────────
default allow := false

allow if {
  _tenant_valid(_claims)
  _role_permitted(_claims)
}

# ── Tenant válido: el claim tenant_id debe existir y no estar vacío ────────────
_tenant_valid(claims) if {
  claims.tenant_id != ""
  claims.tenant_id != null
}

# ── Rol permitido para la ruta y método actuales ──────────────────────────────
_role_permitted(claims) if {
  path   := input.request.path
  method := input.request.method
  roles  := claims.realm_roles
  matched_path := _match_path(path)
  permitted    := route_permissions[matched_path][method]
  some role in roles
  role in permitted
}

# platform_admin puede acceder a cualquier ruta con cualquier método
_role_permitted(claims) if {
  "platform_admin" in claims.realm_roles
}

# Resolución de ruta: match exacto o por prefijo
_match_path(path) := matched if {
  some p in object.keys(route_permissions)
  startswith(path, p)
  matched := p
}

# ── Razón de denegación (útil para logs) ──────────────────────────────────────
reason := "missing or invalid Authorization header" if {
  not allow
  not _claims
}

reason := "missing tenant_id claim" if {
  not allow
  _claims
  not _claims.tenant_id
}

reason := msg if {
  not allow
  _claims
  _claims.tenant_id
  msg := sprintf(
    "role %v not permitted for %v %v",
    [_claims.realm_roles, input.request.method, input.request.path]
  )
}
