"""
Mock del orquestador de agentes de IA.
Expone endpoints que demuestran:
- Fine-grained authz via OPA (Fase 2)
- Control de scopes de agentes (Fase 3)
- Acceso a credenciales en OpenBao controlado por OPA (Fase 4)
"""
from __future__ import annotations

import os
import json
import base64
import logging
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="AI Orchestrator Mock", version="1.0.0")

OPA_URL       = os.getenv("OPA_URL",       "http://opa:8181")
OPENBAO_URL   = os.getenv("OPENBAO_URL",   "http://openbao:8200")
OPENBAO_TOKEN = os.getenv("OPENBAO_TOKEN", "root-token")


# ── OPA helper ────────────────────────────────────────────────────────────────
def opa_query(package_path: str, input_data: dict) -> dict:
    url = f"{OPA_URL}/v1/data/{package_path}"
    resp = httpx.post(url, json={"input": input_data}, timeout=5.0)
    resp.raise_for_status()
    return resp.json().get("result", {})


# ── OpenBao helper ────────────────────────────────────────────────────────────
def openbao_read_secret(path: str) -> dict:
    url  = f"{OPENBAO_URL}/v1/secret/data/{path}"
    resp = httpx.get(url, headers={"X-Vault-Token": OPENBAO_TOKEN}, timeout=5.0)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json().get("data", {}).get("data", {})


def openbao_write_secret(path: str, data: dict) -> None:
    url  = f"{OPENBAO_URL}/v1/secret/data/{path}"
    resp = httpx.post(
        url,
        json={"data": data},
        headers={"X-Vault-Token": OPENBAO_TOKEN},
        timeout=5.0
    )
    resp.raise_for_status()


# ── Identidad del caller ────────────────────────────────────────────────────
# APISIX (openid-connect en /orchestrator/*) ya validó la firma/expiración del
# JWT antes de reenviar la petición; aquí solo se decodifica el payload (sin
# reverificar firma) para construir el "user", nunca a partir del body.
def _decode_jwt_payload(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, UnicodeDecodeError):
        return {}


def get_authenticated_user(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing or invalid Authorization header")

    claims = _decode_jwt_payload(authorization[7:].strip())
    user_id    = claims.get("preferred_username")  # username, no el "sub" (UUID)
    tenant_id  = claims.get("tenant_id")
    if not user_id or not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="token missing required claims (preferred_username, tenant_id)",
        )
    return {
        "id":        user_id,
        "roles":     claims.get("realm_roles") or [],
        "tenant_id": tenant_id,
        "team_id":   claims.get("team_id", ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FASE 2 — Fine-grained: acceso a recurso con input enriquecido
# ══════════════════════════════════════════════════════════════════════════════
class ResourceAccessRequest(BaseModel):
    resource: dict   # { type, id, visibility, owner_id, owner_team_id, tenant_id, sensitivity }
    action:   str
    purpose:  Optional[str] = "agent-assist"


@app.post("/authorize/resource")
def authorize_resource(req: ResourceAccessRequest, user: dict = Depends(get_authenticated_user)):
    """
    Consulta OPA (orchestrator package) para decidir si el usuario
    puede realizar la acción sobre el recurso dado. El usuario se identifica
    decodificando el JWT (ver get_authenticated_user), no por el body.
    """
    opa_input = {
        "user":     user,
        "resource": req.resource,
        "action":   req.action,
        "purpose":  req.purpose,
    }
    result = opa_query("orchestrator", opa_input)
    allowed = result.get("allow", False)

    if allowed:
        return {"allowed": True, "resource_id": req.resource.get("id")}

    reason = result.get("deny_reason", "access denied by policy")
    log.warning("Resource access denied: %s | input=%s", reason, json.dumps(opa_input))
    raise HTTPException(status_code=403, detail={"allowed": False, "reason": reason})


# ══════════════════════════════════════════════════════════════════════════════
# FASE 3 — Scopes de agentes con decisión ternaria
# ══════════════════════════════════════════════════════════════════════════════
class AgentActionRequest(BaseModel):
    agent:  dict   # { id, level, owner_id, tenant_id }
    tool:   str
    action: str


@app.post("/authorize/agent-action")
def authorize_agent_action(req: AgentActionRequest):
    """
    Consulta OPA (agents package) y devuelve:
    - 200 { decision: allow }
    - 202 { decision: pending_approval, required_approver, ttl_seconds }
    - 403 { decision: deny, reason }
    """
    opa_input = {
        "agent":  req.agent,
        "tool":   req.tool,
        "action": req.action,
    }
    result   = opa_query("agents", opa_input)
    decision = result.get("decision", {})

    d = decision.get("decision", "deny")

    if d == "allow":
        return JSONResponse(status_code=200, content=decision)

    if d == "pending_approval":
        return JSONResponse(status_code=202, content=decision)

    # deny
    log.warning("Agent action denied: %s", json.dumps(decision))
    raise HTTPException(status_code=403, detail=decision)


# ══════════════════════════════════════════════════════════════════════════════
# FASE 4 — OpenBao + OPA: credenciales delegadas
# ══════════════════════════════════════════════════════════════════════════════
class SecretAccessRequest(BaseModel):
    agent:        dict   # { id, level, owner_id, tenant_id }
    secret_path:  str    # e.g. "agents/agent-acme-001/credentials/jira"
    operation:    str    # read | write | delete | list
    on_behalf_of: str    # user_id
    secret_data:  Optional[dict] = None  # solo para write


@app.post("/secrets/access")
def secrets_access(req: SecretAccessRequest):
    """
    1. Consulta OPA (secrets package) para validar el acceso
    2. Si está permitido, ejecuta la operación en OpenBao
    """
    opa_input = {
        "agent":        req.agent,
        "secret_path":  req.secret_path,
        "operation":    req.operation,
        "on_behalf_of": req.on_behalf_of,
    }
    result  = opa_query("secrets", opa_input)
    allowed = result.get("allow", False)

    if not allowed:
        reason = result.get("deny_reason", "access denied by policy")
        log.warning("Secret access denied: %s | path=%s", reason, req.secret_path)
        raise HTTPException(status_code=403, detail={"allowed": False, "reason": reason})

    # OPA aprobó — ejecutar la operación en OpenBao
    if req.operation == "read":
        secret = openbao_read_secret(req.secret_path)
        if not secret:
            raise HTTPException(status_code=404, detail="secret not found")
        return {"allowed": True, "data": secret}

    if req.operation == "write":
        if not req.secret_data:
            raise HTTPException(status_code=400, detail="secret_data required for write")
        openbao_write_secret(req.secret_path, req.secret_data)
        return {"allowed": True, "written": True}

    raise HTTPException(status_code=400, detail=f"unsupported operation: {req.operation}")


# ══════════════════════════════════════════════════════════════════════════════
# Health
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    return {"status": "ok"}
