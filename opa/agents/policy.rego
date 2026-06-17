# Política de control de scopes para agentes de IA.
# Salida ternaria: allow | deny | pending_approval
#
# Input:
# {
#   "agent":  { "id", "level": "informativo"|"asesor"|"accionable", "owner_id", "tenant_id" },
#   "tool":   "ticketing" | "knowledge_base" | "observability" | "runbook" | "deployment",
#   "action": "read" | "create" | "update" | "delete" | "execute" | "deploy"
# }
#
# Output:
# { "decision": "allow" }
# { "decision": "deny",             "reason": "..." }
# { "decision": "pending_approval", "required_approver": "...", "ttl_seconds": 3600 }
package agents

import rego.v1

# ── Matriz de permisos por nivel de agente ─────────────────────────────────────
# Cada entrada: tool → { action → "allow" | "deny" | "pending_approval" }
permissions := {
  "informativo": {
    "ticketing":    {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "knowledge_base":{"read": "allow","create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "observability":{"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "runbook":      {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "deployment":   {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"}
  },
  "asesor": {
    "ticketing":    {"read": "allow", "create": "pending_approval", "update": "pending_approval", "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "knowledge_base":{"read": "allow","create": "allow",            "update": "allow",            "delete": "pending_approval", "execute": "deny", "deploy": "deny"},
    "observability":{"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"},
    "runbook":      {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "pending_approval", "deploy": "deny"},
    "deployment":   {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "deny",  "deploy": "deny"}
  },
  "accionable": {
    "ticketing":    {"read": "allow", "create": "allow",            "update": "allow",            "delete": "pending_approval", "execute": "allow", "deploy": "deny"},
    "knowledge_base":{"read": "allow","create": "allow",            "update": "allow",            "delete": "allow", "execute": "deny",  "deploy": "deny"},
    "observability":{"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "allow", "deploy": "deny"},
    "runbook":      {"read": "allow", "create": "deny",             "update": "deny",             "delete": "deny",  "execute": "allow", "deploy": "deny"},
    "deployment":   {"read": "allow", "create": "pending_approval", "update": "pending_approval", "delete": "deny",  "execute": "pending_approval", "deploy": "pending_approval"}
  }
}

# ── Regla principal: calcula la decisión ──────────────────────────────────────
decision := result if {
  raw := permissions[input.agent.level][input.tool][input.action]
  raw == "allow"
  result := {"decision": "allow"}
}

decision := result if {
  raw := permissions[input.agent.level][input.tool][input.action]
  raw == "deny"
  result := {
    "decision": "deny",
    "reason": sprintf(
      "agent level '%v' is not permitted to perform '%v' on tool '%v'",
      [input.agent.level, input.action, input.tool]
    )
  }
}

decision := result if {
  raw := permissions[input.agent.level][input.tool][input.action]
  raw == "pending_approval"
  result := {
    "decision":          "pending_approval",
    "required_approver": input.agent.owner_id,
    "ttl_seconds":       3600,
    "reason": sprintf(
      "action '%v' on tool '%v' by agent level '%v' requires explicit human approval",
      [input.action, input.tool, input.agent.level]
    )
  }
}

# Nivel de agente no reconocido (se evalúa primero para evitar conflicto)
decision := result if {
  not permissions[input.agent.level]
  result := {
    "decision": "deny",
    "reason":   sprintf("unknown agent level: %v", [input.agent.level])
  }
}

# Herramienta o acción no reconocida (solo cuando el nivel sí existe)
decision := result if {
  permissions[input.agent.level]
  not permissions[input.agent.level][input.tool][input.action]
  result := {
    "decision": "deny",
    "reason":   sprintf("unknown tool/action combination: %v/%v", [input.tool, input.action])
  }
}
