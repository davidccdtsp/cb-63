package orchestrator_test

import rego.v1
import data.orchestrator

# ── Helpers ───────────────────────────────────────────────────────────────────
alice := {"id": "alice", "roles": ["user"], "tenant_id": "acme", "team_id": "platform-team"}
bob   := {"id": "bob",   "roles": ["admin"], "tenant_id": "acme", "team_id": "platform-team"}
carol := {"id": "carol", "roles": ["user"], "tenant_id": "globex", "team_id": "ops-team"}
dave  := {"id": "dave",  "roles": ["platform_admin"], "tenant_id": "platform", "team_id": ""}

kb_global  := {"type": "knowledge_base", "id": "kb-1", "visibility": "global",  "owner_id": "bob", "owner_team_id": "platform-team", "tenant_id": "acme", "sensitivity": "low"}
kb_tenant  := {"type": "knowledge_base", "id": "kb-2", "visibility": "tenant",  "owner_id": "bob", "owner_team_id": "platform-team", "tenant_id": "acme", "sensitivity": "low"}
kb_team    := {"type": "knowledge_base", "id": "kb-3", "visibility": "team",    "owner_id": "bob", "owner_team_id": "platform-team", "tenant_id": "acme", "sensitivity": "medium"}
kb_private := {"type": "knowledge_base", "id": "kb-4", "visibility": "private", "owner_id": "alice", "owner_team_id": "platform-team", "tenant_id": "acme", "sensitivity": "low"}
kb_high    := {"type": "knowledge_base", "id": "kb-5", "visibility": "tenant",  "owner_id": "bob", "owner_team_id": "platform-team", "tenant_id": "acme", "sensitivity": "high"}
kb_critical:= {"type": "knowledge_base", "id": "kb-6", "visibility": "global",  "owner_id": "dave", "owner_team_id": "platform-team", "tenant_id": "platform", "sensitivity": "critical"}

mk(user, resource, action) := {"user": user, "resource": resource, "action": action, "purpose": "agent-assist"}

# ── Visibilidad global ────────────────────────────────────────────────────────
test_user_can_read_global_kb if {
  orchestrator.allow with input as mk(alice, kb_global, "read")
}

test_cross_tenant_cannot_read_global_kb if {
  # carol es de globex, kb_global es de acme
  not orchestrator.allow with input as mk(carol, kb_global, "read")
}

# ── Visibilidad tenant ────────────────────────────────────────────────────────
test_same_tenant_user_can_read_tenant_kb if {
  orchestrator.allow with input as mk(alice, kb_tenant, "read")
}

test_cross_tenant_cannot_read_tenant_kb if {
  not orchestrator.allow with input as mk(carol, kb_tenant, "read")
}

# ── Visibilidad team ──────────────────────────────────────────────────────────
test_team_member_can_read_team_kb if {
  orchestrator.allow with input as mk(alice, kb_team, "read")
}

test_same_tenant_different_team_cannot_read_team_kb if {
  other_user := {"id": "eve", "roles": ["user"], "tenant_id": "acme", "team_id": "dev-team"}
  not orchestrator.allow with input as mk(other_user, kb_team, "read")
}

test_admin_can_read_team_kb_of_other_team if {
  # admin del mismo tenant puede leer KB de equipo aunque no pertenezca a ese equipo
  # (bob.team_id = "platform-team" = kb_team.owner_team_id, así que el acceso
  # se concede como miembro de equipo, no por admin override)
  orchestrator.allow with input as mk(bob, kb_team, "read")
}

test_admin_override_for_team_visibility if {
  # admin en un equipo DISTINTO al de la KB → pasa solo por la regla de admin override
  bob_other_team := {"id": "bob", "roles": ["admin"], "tenant_id": "acme", "team_id": "dev-team"}
  orchestrator.allow with input as mk(bob_other_team, kb_team, "read")
}

test_cross_tenant_cannot_read_team_kb if {
  # carol es de globex, kb_team es de acme — cross-tenant siempre deniega
  not orchestrator.allow with input as mk(carol, kb_team, "read")
}

test_user_cannot_write_team_kb if {
  # usuario con rol "user" no puede escribir aunque sea del mismo equipo
  not orchestrator.allow with input as mk(alice, kb_team, "write")
}

# ── Visibilidad private ───────────────────────────────────────────────────────
test_owner_can_read_private_kb if {
  orchestrator.allow with input as mk(alice, kb_private, "read")
}

test_non_owner_cannot_read_private_kb if {
  other := {"id": "eve", "roles": ["user"], "tenant_id": "acme", "team_id": "platform-team"}
  not orchestrator.allow with input as mk(other, kb_private, "read")
}

# ── Sensibilidad ──────────────────────────────────────────────────────────────
test_user_cannot_read_high_sensitivity if {
  not orchestrator.allow with input as mk(alice, kb_high, "read")
}

test_admin_can_read_high_sensitivity if {
  orchestrator.allow with input as mk(bob, kb_high, "read")
}

test_only_platform_admin_can_read_critical if {
  not orchestrator.allow with input as mk(bob, kb_critical, "read")
  orchestrator.allow with input as mk(dave, kb_critical, "read")
}

# ── Escritura ─────────────────────────────────────────────────────────────────
test_user_cannot_write if {
  not orchestrator.allow with input as mk(alice, kb_tenant, "write")
}

test_admin_can_write if {
  orchestrator.allow with input as mk(bob, kb_tenant, "write")
}

# ── Admin restringido a su propio tenant ──────────────────────────────────────
test_admin_of_other_tenant_cannot_write if {
  foreign_admin := {"id": "frank", "roles": ["admin"], "tenant_id": "globex", "team_id": ""}
  not orchestrator.allow with input as mk(foreign_admin, kb_tenant, "write")
}

# ── Conversaciones (recurso con visibilidad y propietario) ────────────────────
conv_alice := {
  "type": "conversation", "id": "conv-1", "visibility": "private",
  "owner_id": "alice", "owner_team_id": "platform-team",
  "tenant_id": "acme", "sensitivity": "low"
}
conv_team := {
  "type": "conversation", "id": "conv-2", "visibility": "team",
  "owner_id": "alice", "owner_team_id": "platform-team",
  "tenant_id": "acme", "sensitivity": "low"
}

test_user_can_read_own_conversation if {
  orchestrator.allow with input as mk(alice, conv_alice, "read")
}

test_non_owner_cannot_read_private_conversation if {
  eve := {"id": "eve", "roles": ["user"], "tenant_id": "acme", "team_id": "platform-team"}
  not orchestrator.allow with input as mk(eve, conv_alice, "read")
}

test_admin_can_read_any_conversation_in_tenant if {
  orchestrator.allow with input as mk(bob, conv_alice, "read")
}

test_team_member_can_read_team_conversation if {
  orchestrator.allow with input as mk(alice, conv_team, "read")
}

test_cross_tenant_cannot_read_conversation if {
  not orchestrator.allow with input as mk(carol, conv_alice, "read")
}

test_platform_admin_can_read_cross_tenant_conversation if {
  orchestrator.allow with input as mk(dave, conv_alice, "read")
}

# ── Agentes como identidades de servicio en el orquestador ───────────────────
agent_accionable_id := {
  "id": "agent-acme-001", "roles": ["agent:accionable"],
  "tenant_id": "acme", "team_id": "platform-team"
}
agent_asesor_id := {
  "id": "agent-acme-002", "roles": ["agent:asesor"],
  "tenant_id": "acme", "team_id": "platform-team"
}

test_agent_accionable_can_read_global_kb if {
  orchestrator.allow with input as mk(agent_accionable_id, kb_global, "read")
}

test_agent_accionable_can_write_team_kb if {
  orchestrator.allow with input as mk(agent_accionable_id, kb_team, "write")
}

test_agent_asesor_cannot_write_kb if {
  not orchestrator.allow with input as mk(agent_asesor_id, kb_tenant, "write")
}

test_agent_cross_tenant_cannot_access_kb if {
  foreign_agent := {
    "id": "agent-globex-001", "roles": ["agent:accionable"],
    "tenant_id": "globex", "team_id": "ops-team"
  }
  not orchestrator.allow with input as mk(foreign_agent, kb_global, "read")
}
