# Política fine-grained para el orquestador de agentes.
# El input llega enriquecido con atributos del recurso, sensibilidad y propósito.
#
# Input shape:
# {
#   "user":     { "id", "roles": [], "tenant_id", "team_id" },
#   "resource": { "type", "id", "visibility", "owner_id", "owner_team_id", "tenant_id", "sensitivity" },
#   "action":   "read" | "write" | "delete" | "share",
#   "purpose":  "agent-assist" | "reporting" | "admin"
# }
package orchestrator

import rego.v1

# ── Niveles de sensibilidad (mayor número = más restrictivo) ──────────────────
sensitivity_level := {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Visibilidad de recursos: quién puede ver qué ──────────────────────────────
# global   → cualquier usuario autenticado del mismo tenant o platform_admin
# tenant   → usuarios del mismo tenant
# team     → usuarios del mismo equipo dentro del tenant
# private  → solo el propietario o admin

default allow := false

allow if {
  _same_tenant
  _visibility_check
  _action_permitted
  _sensitivity_check
}

# platform_admin puede leer cualquier recurso de cualquier tenant
allow if {
  "platform_admin" in input.user.roles
  input.action == "read"
}

# ── Tenant check ──────────────────────────────────────────────────────────────
_same_tenant if {
  input.user.tenant_id == input.resource.tenant_id
}

_same_tenant if {
  "platform_admin" in input.user.roles
}

# ── Visibilidad ───────────────────────────────────────────────────────────────
_visibility_check if {
  input.resource.visibility == "global"
}

_visibility_check if {
  input.resource.visibility == "tenant"
  _same_tenant
}

_visibility_check if {
  input.resource.visibility == "team"
  _same_tenant
  input.user.team_id == input.resource.owner_team_id
}

_visibility_check if {
  input.resource.visibility == "private"
  input.user.id == input.resource.owner_id
}

_visibility_check if {
  input.resource.visibility in {"tenant", "team", "private"}
  "admin" in input.user.roles
  _same_tenant
}

# ── Permisos por acción y rol ─────────────────────────────────────────────────
_action_permitted if {
  input.action in {"read"}
  some role in input.user.roles
  role in {"user", "admin", "platform_admin", "agent:informativo", "agent:asesor", "agent:accionable"}
}

_action_permitted if {
  input.action in {"write", "delete"}
  some role in input.user.roles
  role in {"admin", "platform_admin"}
}

_action_permitted if {
  input.action == "write"
  "agent:accionable" in input.user.roles
  # Los agentes accionables pueden escribir en recursos de team o tenant
  input.resource.visibility in {"team", "tenant"}
}

# ── Sensibilidad: roles restringidos no pueden acceder a datos críticos ────────
_sensitivity_check if {
  level := sensitivity_level[input.resource.sensitivity]
  level <= 2  # low o medium: sin restricción adicional
}

_sensitivity_check if {
  level := sensitivity_level[input.resource.sensitivity]
  level == 3  # high: solo admin o platform_admin
  some role in input.user.roles
  role in {"admin", "platform_admin"}
}

_sensitivity_check if {
  level := sensitivity_level[input.resource.sensitivity]
  level == 4  # critical: solo platform_admin
  "platform_admin" in input.user.roles
}

# ── Razón de denegación ───────────────────────────────────────────────────────
deny_reason := "cross-tenant access denied" if {
  not _same_tenant
}

deny_reason := msg if {
  _same_tenant
  not _visibility_check
  msg := sprintf("resource visibility '%v' restricts access", [input.resource.visibility])
}

deny_reason := msg if {
  _same_tenant
  _visibility_check
  not _sensitivity_check
  msg := sprintf("sensitivity level '%v' requires elevated privileges", [input.resource.sensitivity])
}
