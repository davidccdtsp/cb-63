# Política de control de acceso a secretos en OpenBao.
# OPA actúa como capa de autorización antes de que el orquestador
# solicite un token de acceso a OpenBao.
#
# Input:
# {
#   "agent":      { "id", "level", "owner_id", "tenant_id" },
#   "secret_path": "agents/{agent_id}/credentials/{service}",
#   "operation":  "read" | "write" | "delete" | "list",
#   "on_behalf_of": "user_id"   # usuario en cuyo nombre actúa el agente
# }
package secrets

import rego.v1

# ── Operaciones permitidas por nivel de agente ────────────────────────────────
allowed_ops_by_level := {
  "informativo": {"read"},
  "asesor":      {"read"},
  "accionable":  {"read", "write"}
}

# ── Path esperado para un agente accediendo a sus propias credenciales ─────────
expected_path_prefix(agent_id) := sprintf("agents/%v/credentials/", [agent_id])

# ── Regla principal ───────────────────────────────────────────────────────────
default allow := false

allow if {
  _valid_agent_path
  _operation_permitted
  _on_behalf_valid
}

# El path del secreto debe corresponder al propio agente
_valid_agent_path if {
  prefix := expected_path_prefix(input.agent.id)
  startswith(input.secret_path, prefix)
}

# La operación debe estar dentro de las permitidas para el nivel del agente
_operation_permitted if {
  ops := allowed_ops_by_level[input.agent.level]
  input.operation in ops
}

# El usuario on_behalf_of debe ser el propietario del agente
# (evita que un agente acceda a credenciales delegadas de otro usuario)
_on_behalf_valid if {
  input.on_behalf_of == input.agent.owner_id
}

# ── Razones de denegación ─────────────────────────────────────────────────────
deny_reason := "agent cannot access credentials of another agent" if {
  not _valid_agent_path
}

deny_reason := msg if {
  _valid_agent_path
  not _operation_permitted
  msg := sprintf("agent level '%v' cannot perform '%v' on secrets", [input.agent.level, input.operation])
}

deny_reason := msg if {
  _valid_agent_path
  _operation_permitted
  not _on_behalf_valid
  msg := sprintf(
    "agent owner '%v' does not match on_behalf_of user '%v'",
    [input.agent.owner_id, input.on_behalf_of]
  )
}

# ── Path del OpenBao token policy (generado dinámicamente) ───────────────────
# Si OPA aprueba, el orquestador usará este path al solicitar el secreto a OpenBao
openbao_policy_path := input.secret_path if { allow }
