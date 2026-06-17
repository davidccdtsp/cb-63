package agents_test

import rego.v1
import data.agents

# ── Helpers ───────────────────────────────────────────────────────────────────
agent(level) := {
  "id":        sprintf("agent-%v-001", [level]),
  "level":     level,
  "owner_id":  "alice",
  "tenant_id": "acme"
}

mk(level, tool, action) := {
  "agent":  agent(level),
  "tool":   tool,
  "action": action
}

# ── INFORMATIVO: solo lectura ─────────────────────────────────────────────────
test_informativo_can_read_ticketing if {
  agents.decision.decision == "allow" with input as mk("informativo", "ticketing", "read")
}

test_informativo_cannot_create_ticketing if {
  d := agents.decision with input as mk("informativo", "ticketing", "create")
  d.decision == "deny"
}

test_informativo_cannot_read_knowledge_base if {
  # informativo SÍ puede leer knowledge_base
  agents.decision.decision == "allow" with input as mk("informativo", "knowledge_base", "read")
}

test_informativo_cannot_execute_runbook if {
  d := agents.decision with input as mk("informativo", "runbook", "execute")
  d.decision == "deny"
}

# ── ASESOR: lectura + proponer (pending_approval) ─────────────────────────────
test_asesor_can_read_ticketing if {
  agents.decision.decision == "allow" with input as mk("asesor", "ticketing", "read")
}

test_asesor_create_ticketing_requires_approval if {
  d := agents.decision with input as mk("asesor", "ticketing", "create")
  d.decision == "pending_approval"
  d.required_approver == "alice"
  d.ttl_seconds == 3600
}

test_asesor_execute_runbook_requires_approval if {
  d := agents.decision with input as mk("asesor", "runbook", "execute")
  d.decision == "pending_approval"
}

test_asesor_cannot_deploy if {
  d := agents.decision with input as mk("asesor", "deployment", "deploy")
  d.decision == "deny"
}

# ── ACCIONABLE: puede ejecutar, deploy siempre requiere aprobación ─────────────
test_accionable_can_create_ticketing if {
  agents.decision.decision == "allow" with input as mk("accionable", "ticketing", "create")
}

test_accionable_can_execute_runbook if {
  agents.decision.decision == "allow" with input as mk("accionable", "runbook", "execute")
}

test_accionable_deploy_requires_approval if {
  d := agents.decision with input as mk("accionable", "deployment", "deploy")
  d.decision == "pending_approval"
  d.required_approver == "alice"
}

test_accionable_execute_deployment_requires_approval if {
  d := agents.decision with input as mk("accionable", "deployment", "execute")
  d.decision == "pending_approval"
}

# ── Herramienta compartida con permisos distintos por nivel ───────────────────
# ticketing/create: informativo→deny, asesor→pending_approval, accionable→allow
test_ticketing_create_differs_by_level if {
  di := agents.decision with input as mk("informativo", "ticketing", "create")
  da := agents.decision with input as mk("asesor",       "ticketing", "create")
  dc := agents.decision with input as mk("accionable",   "ticketing", "create")

  di.decision == "deny"
  da.decision == "pending_approval"
  dc.decision == "allow"
}

# ── Nivel desconocido ─────────────────────────────────────────────────────────
test_unknown_level_denied if {
  d := agents.decision with input as mk("superagente", "ticketing", "read")
  d.decision == "deny"
}
