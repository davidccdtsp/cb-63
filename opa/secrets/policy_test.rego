package secrets_test

import rego.v1
import data.secrets

agent_accionable := {
  "id":        "agent-acme-001",
  "level":     "accionable",
  "owner_id":  "alice",
  "tenant_id": "acme"
}

agent_asesor := {
  "id":        "agent-acme-002",
  "level":     "asesor",
  "owner_id":  "alice",
  "tenant_id": "acme"
}

mk(agent, path, op, behalf) := {
  "agent":        agent,
  "secret_path":  path,
  "operation":    op,
  "on_behalf_of": behalf
}

# ── CASOS POSITIVOS ───────────────────────────────────────────────────────────
test_accionable_can_read_own_credentials if {
  secrets.allow with input as mk(
    agent_accionable,
    "agents/agent-acme-001/credentials/jira",
    "read",
    "alice"
  )
}

test_asesor_can_read_own_credentials if {
  secrets.allow with input as mk(
    agent_asesor,
    "agents/agent-acme-002/credentials/confluence",
    "read",
    "alice"
  )
}

test_accionable_can_write_own_credentials if {
  secrets.allow with input as mk(
    agent_accionable,
    "agents/agent-acme-001/credentials/jira",
    "write",
    "alice"
  )
}

# ── CASOS NEGATIVOS ───────────────────────────────────────────────────────────
test_agent_cannot_read_other_agent_credentials if {
  not secrets.allow with input as mk(
    agent_accionable,
    "agents/agent-acme-002/credentials/jira",  # path de otro agente
    "read",
    "alice"
  )
}

test_asesor_cannot_write_credentials if {
  not secrets.allow with input as mk(
    agent_asesor,
    "agents/agent-acme-002/credentials/jira",
    "write",
    "alice"
  )
}

test_wrong_on_behalf_denied if {
  not secrets.allow with input as mk(
    agent_accionable,
    "agents/agent-acme-001/credentials/jira",
    "read",
    "eve"  # no es el propietario del agente
  )
}

test_informativo_cannot_write if {
  agent_info := {
    "id":        "agent-acme-003",
    "level":     "informativo",
    "owner_id":  "alice",
    "tenant_id": "acme"
  }
  not secrets.allow with input as mk(
    agent_info,
    "agents/agent-acme-003/credentials/pagerduty",
    "write",
    "alice"
  )
}

# ── Deny reason ───────────────────────────────────────────────────────────────
test_deny_reason_wrong_path if {
  r := secrets.deny_reason with input as mk(
    agent_accionable,
    "agents/agent-acme-002/credentials/jira",
    "read",
    "alice"
  )
  r == "agent cannot access credentials of another agent"
}
