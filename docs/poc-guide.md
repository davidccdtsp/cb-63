# PoC: Autorización con OPA + Apache APISIX + Keycloak + OpenBao

## Índice

1. [Arquitectura general](#1-arquitectura-general)
2. [Setup del entorno](#2-setup-del-entorno)
3. [Configuración de los plugins en APISIX](#3-configuración-de-los-plugins-en-apisix-scriptsinit-apisixsh)
4. [Coarse-grained en el gateway](#4-coarse-grained-en-el-gateway)
5. [Fine-grained en el orquestador](#5-fine-grained-en-el-orquestador)
6. [Control de scopes de agentes (decisión ternaria)](#6-control-de-scopes-de-agentes-decisión-ternaria)
7. [OpenBao + OPA: credenciales delegadas](#7-openbao--opa-credenciales-delegadas)
8. [Comparativa OPA vs Keycloak Authorization Services](#8-comparativa-opa-vs-keycloak-authorization-services)
9. [Referencias y documentación oficial](#9-referencias-y-documentación-oficial)

---

## 1. Arquitectura general

Esta PoC implementa **dos flujos independientes**, alcanzables por rutas distintas de APISIX. No están encadenados: el gateway nunca reenvía al orquestador el resultado de su evaluación, y el orquestador nunca pasa por el plugin `opa` del gateway. Cada flujo demuestra un nivel de autorización distinto.

### Flujo A — Coarse-grained en el gateway

Rutas `/api/conversations`, `/api/agents/run`, `/api/knowledge`, `/api/admin`. El upstream es **`mock-backend`**, un nginx que solo devuelve JSON fijo (no hay lógica de negocio real).

```
┌──────────────┐        ┌─────────────────────────────────────────────────┐
│   Cliente    │──JWT──▶│               Apache APISIX                     │
│  (usuario /  │        │  plugin: openid-connect (Keycloak)              │
│   agente)    │        │  plugin: opa ──▶ OPA /v1/data/gateway           │
└──────────────┘        │         (coarse-grained: rol + tenant + ruta)   │
                        └───────────────────┬─────────────────────────────┘
                                            │ si allow = true
                                            ▼
                                   mock-backend (nginx, JSON fijo)
```

1. El cliente se autentica en Keycloak y obtiene un JWT con claims: `sub`, `tenant_id`, `team_id`, `realm_roles`.
2. La petición llega a APISIX con `Authorization: Bearer <JWT>`.
3. El plugin `openid-connect` valida el JWT contra Keycloak (introspection o JWKS).
4. El plugin `opa` envía la petición HTTP (incluyendo el header `Authorization` con el JWT raw) a OPA (`/v1/data/gateway`). La política Rego decodifica el JWT con `io.jwt.decode`.
5. OPA evalúa la política coarse-grained: ¿el rol está permitido para esta ruta y método?
6. Si OPA devuelve `{"result": {"allow": true}}`, APISIX enruta al `mock-backend`; si no, responde 403 sin llegar al backend.

### Flujo B — Fine-grained en el orquestador

El orquestador **solo es alcanzable a través de APISIX** (`/orchestrator/*`): no publica su puerto al host (`docker-compose.yml` no le mapea `ports`), solo es visible dentro de la red `poc`. Esa ruta lleva `openid-connect` (igual que el Flujo A), que valida el JWT antes de reenviar la petición. La autorización fine-grained la hace **el propio orquestador**, consultando tres paquetes Rego distintos al `gateway` del Flujo A.

```
┌──────────────┐        ┌──────────────────────────────────────────────────┐
│   Cliente /  │──JWT──▶│  APISIX (/orchestrator/*, solo openid-connect)    │
│   Agente     │        └───────────────────┬──────────────────────────────┘
└──────────────┘                            │ body tal cual + Authorization: Bearer <JWT>
                                             ▼
                        ┌──────────────────────────────────────────────────┐
                        │           Orquestador de Agentes (FastAPI)       │
                        │  decodifica el JWT del header Authorization      │
                        │  (ya validado por APISIX) ──▶ construye "user"   │
                        │  POST /v1/data/orchestrator ──▶ OPA              │
                        │  (fine-grained: ABAC, visibilidad, sensibilidad) │
                        │  POST /v1/data/agents ──▶ OPA                    │
                        │  (scopes: allow | deny | pending_approval)       │
                        │  POST /v1/data/secrets ──▶ OPA                   │
                        │  (credenciales delegadas ──▶ OpenBao)            │
                        └──────────────────────────────────────────────────┘
```

7. APISIX valida el JWT con `openid-connect` y reenvía la petición tal cual (body sin tocar, header `Authorization` propagado).
8. El orquestador (`get_authenticated_user` en `orchestrator/app.py`) decodifica él mismo el payload del JWT del header `Authorization` para construir el `user` que envía a OPA en `/authorize/resource` — **nunca a partir del body**. No reverifica la firma (ya lo hizo APISIX); si el header falta o el token no tiene los claims esperados, responde 401. El resto del input (`resource.visibility`, `resource.sensitivity`, `agent`, `secret_path`...) sigue viniendo tal cual del body: el orquestador no lo enriquece ni lo valida, es responsabilidad del caller. Ver la sección 3 para la comparativa con la alternativa de extraer estos claims en APISIX en vez de en el orquestador.
9. El orquestador consulta OPA (paquete `orchestrator`, `agents` o `secrets` según el endpoint) y actúa según la decisión: para `/secrets/access`, si OPA permite, lee o escribe el secreto en OpenBao.

```
  ┌──────────────┐   ┌─────────┐   ┌──────────────┐
  │   Keycloak   │   │   OPA   │   │   OpenBao    │
  │  (IdP/JWT)   │   │ (Rego)  │   │ (KV secrets) │
  └──────────────┘   └─────────┘   └──────────────┘
```

---

## 2. Setup del entorno

### Prerrequisitos

- Docker ≥ 24 con Docker Compose v2
- `curl`, `jq` (para los Ejemplo de uso)
- Puertos libres: 8080, 8181, 8200, 9080, 9090, 9092

> El orquestador (puerto interno 8000) **no se publica al host**: solo es alcanzable desde APISIX dentro de la red `poc`. Ver Flujo B en la sección 1.

### Levantar el stack

```bash
git clone <este-repo>
cd opa-apisix-keycloak

# Levantar todos los servicios
docker compose up -d

# Esperar a que Keycloak esté listo (~60s en el primer arranque)
docker compose logs -f keycloak | grep -m1 "Running the server"
```

### Inicializar APISIX y OpenBao

```bash
# Configura rutas y plugins en APISIX
./scripts/init-apisix.sh

# Inicializa OpenBao con KV engine y secretos de demo
./scripts/init-openbao.sh
```

### Obtener tokens de prueba

```bash
# Usuario alice (rol: user, tenant: acme)
export TOKEN_ALICE=$(./scripts/get-token.sh alice alice123 | grep ^TOKEN= | cut -d= -f2-)

# Usuario bob (rol: admin, tenant: acme)
export TOKEN_BOB=$(./scripts/get-token.sh bob bob123 | grep ^TOKEN= | cut -d= -f2-)

# Usuario carol (rol: user, tenant: globex)
export TOKEN_CAROL=$(./scripts/get-token.sh carol carol123 | grep ^TOKEN= | cut -d= -f2-)
```

---

## 3. Configuración de los plugins en APISIX (`scripts/init-apisix.sh`)

El script `scripts/init-apisix.sh` configura, vía Admin API, dos plugins en cada ruta protegida: `openid-connect` (autenticación contra Keycloak) y `opa` (autorización coarse-grained). Se aplican **por ruta**, no de forma global, para poder excluir rutas concretas (p. ej. `/orchestrator/*` solo lleva `openid-connect`, ya que la autorización fine-grained la hace el propio orquestador internamente).

#### Plugin `openid-connect`

```json
{
  "client_id": "apisix",
  "client_secret": "apisix-client-secret",
  "discovery": "http://keycloak:8080/realms/ai-platform/.well-known/openid-configuration",
  "introspection_endpoint": "http://keycloak:8080/realms/ai-platform/protocol/openid-connect/token/introspect",
  "scope": "openid profile email",
  "bearer_only": true,
  "realm": "ai-platform",
  "introspection_endpoint_auth_method": "client_secret_post",
  "set_access_token_header": true,
  "access_token_in_authorization_header": true
}
```

- `client_id` / `client_secret`: credenciales del cliente confidencial `apisix` registrado en el realm de Keycloak; se usan para autenticar las llamadas de introspección.
- `discovery`: URL del documento OIDC discovery de Keycloak; APISIX lo usa para resolver automáticamente el resto de endpoints (`authorization_endpoint`, `jwks_uri`, etc.).
- `introspection_endpoint` + `introspection_endpoint_auth_method`: en vez de validar el JWT localmente contra el JWKS, APISIX valida cada token llamando a Keycloak (RFC 7662). Más costoso en latencia, pero permite revocación inmediata de tokens.
- `bearer_only: true`: la ruta no inicia un flujo de login (no redirige a Keycloak); solo acepta un `Authorization: Bearer <JWT>` ya emitido.
- `set_access_token_header` + `access_token_in_authorization_header`: asegura que, tras la validación, el token siga propagándose en el header `Authorization` hacia el upstream y hacia el plugin `opa` que se ejecuta después en la cadena.

Referencia oficial: [Plugin openid-connect de APISIX](https://apisix.apache.org/docs/apisix/plugins/openid-connect/).

#### Plugin `opa`

```json
{
  "host": "http://opa:8181",
  "policy": "gateway",
  "timeout": 3000
}
```

- `host`: endpoint del servidor OPA dentro de la red `poc` definida en `docker-compose.yml`.
- `policy`: nombre del paquete Rego a consultar; APISIX construye la URL `POST {host}/v1/data/{policy}` (en este caso `http://opa:8181/v1/data/gateway`), que es la misma que se usa en la consulta manual de debug más abajo.
- `timeout`: tiempo máximo (ms) que APISIX espera la respuesta de OPA antes de fallar la petición.

El plugin `opa` se ejecuta **después** de `openid-connect` en la cadena de plugins de la ruta, por lo que el input que recibe OPA en `input.request.headers.authorization` ya contiene el JWT validado (ver formato completo del input en la sección anterior).

Referencia oficial: [Plugin OPA de APISIX](https://apisix.apache.org/docs/apisix/plugins/opa/).

#### Identidad del caller en `/orchestrator/*`: dos aproximaciones posibles

La ruta `/orchestrator/*` solo lleva `openid-connect` (autentica, pero no autoriza). El orquestador necesita saber **quién** hizo la petición para construir el `user` que le pasa a OPA en `/authorize/resource` (ver sección 5). Hay dos formas razonables de resolver esto, y esta PoC implementa la **opción B**:

**Opción A — APISIX extrae los claims y los pasa como headers.** Un plugin `serverless-pre-function` (Lua), configurado con prioridad explícita para ejecutarse *después* de `openid-connect` en la misma fase, decodifica el JWT y añade headers (`X-User-Id`, `X-User-Tenant-Id`, etc.) antes de reenviar al orquestador. Este, simplemente, lee esos headers.

**Opción B — el orquestador decodifica el JWT él mismo (implementada aquí).** APISIX solo autentica (`openid-connect`) y reenvía la petición tal cual, con el JWT en el header `Authorization` (ya propagado gracias a `access_token_in_authorization_header: true`, ver más arriba). El propio orquestador (`get_authenticated_user` en `orchestrator/app.py`) decodifica el payload del JWT — sin reverificar firma, eso ya lo hizo APISIX — para construir el `user`.

| | Opción A (headers desde APISIX) | Opción B (decodifica el orquestador) |
|---|---|---|
| Componentes nuevos en APISIX | Sí: plugin `serverless-pre-function` con Lua a medida, prioridad ajustada a mano para ir después de `openid-connect` | Ninguno: la ruta solo necesita `openid-connect`, igual que el resto de rutas |
| Dónde vive el conocimiento de los claims de Keycloak (`tenant_id`, `team_id`, `realm_roles`, `preferred_username`) | En el borde (Lua), desacoplado del código de negocio | En el propio orquestador (Python) |
| Testing | Requiere APISIX corriendo para probar el Lua (o un runtime Lua aparte) | Test unitario normal de Python |
| Reutilización si hay más servicios detrás de APISIX | Cada servicio nuevo solo lee headers planos, sin librería de JWT | Cada servicio nuevo tiene que decodificar el JWT por su cuenta |
| Acoplamiento a la versión de APISIX | Depende de un detalle interno y no muy documentado (prioridad por defecto de cada plugin: `openid-connect` = 2599, `serverless-pre-function` = 10000) | Ninguno |
| Complejidad para esta PoC | Mayor (Lua + `jq` para inyectarlo en `init-apisix.sh` sin escapar comillas a mano) | Menor: un puñado de líneas en `app.py` |

**Por qué se eligió la opción B aquí**: solo hay un servicio detrás de esa ruta (el orquestador), así que el beneficio principal de la opción A — centralizar el parseo de JWT una vez para que lo reutilicen *varios* servicios — no aplica. La seguridad real es idéntica en ambos casos: la garantía de que solo APISIX puede llegar al orquestador la da que el puerto 8000 no se publica al host (`docker-compose.yml`), no quién decodifica el JWT. Si en el futuro hay más servicios detrás del gateway que necesiten esta misma identidad, migrar a la opción A evita duplicar la lógica de parseo en cada uno. Por otro lado mantiene una configuración de APISIX sencilla y rápida.

Referencia oficial: [Plugin serverless-pre-function de APISIX](https://apisix.apache.org/docs/apisix/plugins/serverless/) (opción A, no usado en este repo).

---

# Casos de uso
Las siguientes secciones ilustran ambos flujos por separado: "Coarse-grained en el gateway" cubre el Flujo A; "Fine-grained en el orquestador", "Control de scopes de agentes" y "OpenBao + OPA" cubren el Flujo B, cada una sobre un endpoint y un paquete Rego distintos.

## 4. Coarse-grained en el gateway

El plugin `opa` de APISIX intercepta cada petición y envía a OPA un input con la forma:

```json
{
    "type": "http",
    "request": {
        "scheme": "http",
        "path": "\/get",
        "headers": {
            "user-agent": "curl\/7.68.0",
            "accept": "*\/*",
            "host": "127.0.0.1:9080"
        },
        "query": {},
        "port": 9080,
        "method": "GET",
        "host": "127.0.0.1"
    },
    "var": {
        "timestamp": 1701234567,
        "server_addr": "127.0.0.1",
        "server_port": "9080",
        "remote_port": "port",
        "remote_addr": "ip address"
    },
    "route": {},
    "service": {},
    "consumer": {}
}
```

> **Nota**: el plugin OPA de APISIX 3.x **no decodifica el JWT**. El token llega como string en `input.request.headers.authorization`. La política Rego lo decodifica internamente con `io.jwt.decode(token)` (sin verificar firma, ya validada por Keycloak en el paso anterior). Los campos opcionales `route`, `consumer` y `service` se incluyen solo si se activan con `with_route`, `with_consumer` o `with_service` en la configuración del plugin.

OPA evalúa `data.gateway.allow` y devuelve `true` o `false`. Si es `false`, APISIX responde 403 sin consultar al backend. La política se encuentra definida en [`gateway/policy.rego`](../opa/gateway/policy.rego) y se estructura del siguiente modo:
- Definición del objeto que contiene la tabla de permisos para ruta + método + roles.
```rego
route_permissions := {
  "/api/conversations": {
    "GET":    {"user", "admin", "platform_admin"},
    "POST":   {"user", "admin", "platform_admin"},
    "DELETE": {"admin", "platform_admin"}
  }
}
```
- Extracción de la información relevante del token.
```rego
_claims := payload if {
  auth := input.request.headers.authorization
  startswith(auth, "Bearer ")
  tok := substring(auth, 7, -1)
  [_, payload, _] := io.jwt.decode(tok)
}
```
- Definición de las reglas. Sección que contiene el conjunto de reglas aplicables dentro de la política, puede contener variables, queries...
```rego
default allow := false

allow if {
  _tenant_valid(_claims)
  _role_permitted(_claims)
}

_tenant_valid(claims) if {
  claims.tenant_id != ""
  claims.tenant_id != null
}
```


### Ejemplo de uso

#### ✓ alice (user) puede leer conversaciones

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  http://localhost:9080/api/conversations
# Esperado: 200
```

#### ✗ alice (user) no puede borrar conversaciones

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  http://localhost:9080/api/conversations
# Esperado: 403
```

#### ✓ bob (admin) puede borrar conversaciones

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN_BOB" \
  http://localhost:9080/api/conversations
# Esperado: 200
```

#### ✗ carol (user de globex) no puede leer conversaciones de acme

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_CAROL" \
  http://localhost:9080/api/conversations
# Esperado: 403 (tenant inválido en política gateway, si se añade check de tenant)
```

#### Consulta directa a OPA (debug)

```bash
# Obtener token de alice primero
TOKEN_ALICE=$(./scripts/get-token.sh alice alice123 | grep ^TOKEN= | cut -d= -f2-)

# Simular el input exacto que APISIX envía a OPA
curl -s -X POST http://localhost:8181/v1/data/gateway \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": {
      \"type\": \"http\",
      \"request\": {
        \"method\": \"DELETE\",
        \"path\": \"/api/conversations\",
        \"headers\": { \"authorization\": \"Bearer $TOKEN_ALICE\" }
      }
    }
  }" | jq .result
# {
#   "allow": false,
#   "reason": "role [\"user\"] not permitted for DELETE /api/conversations"
# }
```

### Tests automáticos

```bash
docker run --rm \
  -v $(pwd)/opa:/policies \
  openpolicyagent/opa:1.17.1-debug \
  test /policies/gateway -v
```

---

## 5. Fine-grained en el orquestador

El input que llega a OPA combina dos orígenes: el `user` lo construye el orquestador decodificando el JWT del header `Authorization` (ver sección 3) — nunca del body — y `resource`/`action`/`purpose` vienen tal cual en el body de la petición. La política ABAC evalúa simultáneamente:

- **Tenant**: el usuario debe pertenecer al mismo tenant que el recurso
- **Visibilidad**: `global` | `tenant` | `team` | `private`
- **Sensibilidad**: `low` | `medium` | `high` | `critical`
- **Acción**: `read` | `write` | `delete`

La política se encuentra definida en [`orchestrator/policy.rego`](../opa/orchestrator/policy.rego) y se estructura del siguiente modo:
- Definición de los niveles de sensibilidad, usados para restringir el acceso a datos críticos.
```rego
sensitivity_level := {"low": 1, "medium": 2, "high": 3, "critical": 4}
```
- Comprobaciones auxiliares sobre el input (tenant, visibilidad, sensibilidad), evaluadas de forma independiente y combinadas después en la regla principal.
```rego
_visibility_check if {
  input.resource.visibility == "team"
  _same_tenant
  input.user.team_id == input.resource.owner_team_id
}

_sensitivity_check if {
  level := sensitivity_level[input.resource.sensitivity]
  level == 3  # high: solo admin o platform_admin
  some role in input.user.roles
  role in {"admin", "platform_admin"}
}
```
- Definición de las reglas. `allow` combina las cuatro comprobaciones (tenant, visibilidad, acción, sensibilidad); existe una regla adicional que permite a `platform_admin` leer cualquier recurso sin pasar por el resto de checks.
```rego
default allow := false

allow if {
  _same_tenant
  _visibility_check
  _action_permitted
  _sensitivity_check
}

allow if {
  "platform_admin" in input.user.roles
  input.action == "read"
}
```

### Ejemplo de uso

#### ✓ alice puede leer una knowledge base de visibilidad global

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "knowledge_base", "id": "kb-1", "visibility": "global",
                  "owner_id": "bob", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "low" },
    "action":   "read",
    "purpose":  "agent-assist"
  }' | jq .
# { "allowed": true, "resource_id": "kb-1" }
```

> Nótese que ya no se envía `user` en el body: `id`, `tenant_id`, `team_id` y `roles` los obtiene el orquestador decodificando el JWT de `$TOKEN_ALICE` (ver sección 3).

#### ✗ carol (globex) no puede leer una KB de acme aunque sea global

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_CAROL" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "knowledge_base", "id": "kb-1", "visibility": "global",
                  "owner_id": "bob", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "low" },
    "action":   "read"
  }' | jq .
# 403: { "detail": { "allowed": false, "reason": "cross-tenant access denied" } }
```

#### ✗ alice no puede leer dato de sensibilidad alta

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "knowledge_base", "id": "kb-5", "visibility": "tenant",
                  "owner_id": "bob", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "high" },
    "action":   "read"
  }' | jq .
# 403: sensitivity level 'high' requires elevated privileges
```

#### ✓ bob (admin) sí puede leer dato de sensibilidad alta

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_BOB" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "knowledge_base", "id": "kb-5", "visibility": "tenant",
                  "owner_id": "bob", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "high" },
    "action":   "read"
  }' | jq .
# { "allowed": true, "resource_id": "kb-5" }
```

#### ✗ Sin token — 401

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Content-Type: application/json" \
  -d '{"resource": {"id": "kb-1"}, "action": "read"}'
# 401: el plugin openid-connect rechaza la petición antes de llegar al orquestador
```

#### ✓ alice lee su propia conversación (allow)

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "conversation", "id": "conv-1", "visibility": "private",
                  "owner_id": "alice", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "low" },
    "action":   "read",
    "purpose":  "agent-assist"
  }' | jq .
# { "allowed": true, "resource_id": "conv-1" }
```

#### ✓ bob (admin) puede leer cualquier conversación del tenant

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_BOB" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "conversation", "id": "conv-1", "visibility": "private",
                  "owner_id": "alice", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "low" },
    "action":   "read"
  }' | jq .
# { "allowed": true, "resource_id": "conv-1" }
```

#### ✗ carol (globex) no puede acceder a conversaciones de acme

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/resource \
  -H "Authorization: Bearer $TOKEN_CAROL" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": { "type": "conversation", "id": "conv-1", "visibility": "private",
                  "owner_id": "alice", "owner_team_id": "platform-team",
                  "tenant_id": "acme", "sensitivity": "low" },
    "action":   "read"
  }' | jq .
# 403: { "detail": { "allowed": false, "reason": "cross-tenant access denied" } }
```

#### Agentes como identidades de servicio — consulta directa a OPA

Los agentes no tienen cuenta propia en Keycloak en esta PoC (no hay token de agente), así que se consulta OPA directamente para mostrar la misma lógica que aplica cuando el orquestador construye el `user` a partir de la identidad de un agente.

#### ✓ Agente accionable lee KB global (allow)

```bash
curl -s -X POST http://localhost:8181/v1/data/orchestrator \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user":     { "id": "agent-acme-001", "roles": ["agent:accionable"],
                    "tenant_id": "acme", "team_id": "platform-team" },
      "resource": { "type": "knowledge_base", "id": "kb-1", "visibility": "global",
                    "owner_id": "bob", "owner_team_id": "platform-team",
                    "tenant_id": "acme", "sensitivity": "low" },
      "action":   "read",
      "purpose":  "agent-assist"
    }
  }' | jq .result
# { "allow": true }
```

#### ✓ Agente accionable escribe en KB de equipo (allow)

```bash
curl -s -X POST http://localhost:8181/v1/data/orchestrator \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user":     { "id": "agent-acme-001", "roles": ["agent:accionable"],
                    "tenant_id": "acme", "team_id": "platform-team" },
      "resource": { "type": "knowledge_base", "id": "kb-3", "visibility": "team",
                    "owner_id": "bob", "owner_team_id": "platform-team",
                    "tenant_id": "acme", "sensitivity": "medium" },
      "action":   "write"
    }
  }' | jq .result
# { "allow": true }
```

#### ✗ Agente asesor no puede escribir en una KB (deny)

```bash
curl -s -X POST http://localhost:8181/v1/data/orchestrator \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user":     { "id": "agent-acme-002", "roles": ["agent:asesor"],
                    "tenant_id": "acme", "team_id": "platform-team" },
      "resource": { "type": "knowledge_base", "id": "kb-2", "visibility": "tenant",
                    "owner_id": "bob", "owner_team_id": "platform-team",
                    "tenant_id": "acme", "sensitivity": "low" },
      "action":   "write"
    }
  }' | jq .result
# { "allow": false }
```

### Tests automáticos

```bash
docker run --rm \
  -v $(pwd)/opa:/policies \
  openpolicyagent/opa:1.17.1-debug \
  test /policies/orchestrator -v
```

---

## 6. Control de scopes de agentes (decisión ternaria)

### Modelo de decisión

OPA devuelve uno de tres estados:

| Estado | HTTP | Significado |
|--------|------|-------------|
| `allow` | 200 | El agente puede ejecutar la acción autónomamente |
| `pending_approval` | 202 | La acción requiere aprobación explícita del responsable |
| `deny` | 403 | La acción está prohibida para este nivel de agente |

### Matriz de permisos (extracto)

| Herramienta | Acción | informativo | asesor | accionable |
|-------------|--------|-------------|--------|------------|
| ticketing | read | ✅ allow | ✅ allow | ✅ allow |
| ticketing | create | ❌ deny | ⏳ pending | ✅ allow |
| ticketing | delete | ❌ deny | ❌ deny | ⏳ pending |
| runbook | execute | ❌ deny | ⏳ pending | ✅ allow |
| deployment | deploy | ❌ deny | ❌ deny | ⏳ pending |
| knowledge_base | write | ❌ deny | ✅ allow | ✅ allow |

La política se encuentra definida en [`agents/policy.rego`](../opa/agents/policy.rego) y se estructura del siguiente modo:
- Definición de la matriz de permisos: nivel de agente → herramienta → acción → resultado (`allow` | `deny` | `pending_approval`). Es la fuente única de la tabla mostrada arriba.
```rego
permissions := {
  "asesor": {
    "ticketing":     {"read": "allow", "create": "pending_approval", "update": "pending_approval", "delete": "deny", "execute": "deny", "deploy": "deny"},
    "knowledge_base":{"read": "allow", "create": "allow",            "update": "allow",            "delete": "pending_approval", "execute": "deny", "deploy": "deny"}
  }
}
```
- Definición de las reglas. `decision` busca el valor en la matriz según `input.agent.level`, `input.tool` e `input.action`, y construye la respuesta ternaria correspondiente.
```rego
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
```

### Ejemplo de uso

> Igual que en la sección anterior, todas las llamadas pasan por APISIX y requieren `Authorization: Bearer <token>` (el plugin `openid-connect` de la ruta `/orchestrator/*` lo exige), aunque esta política no use la identidad del usuario — solo `agent`, `tool` y `action` del body.

#### ✓ Agente accionable crea ticket (allow)

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/agent-action \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":  { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
    "tool":   "ticketing",
    "action": "create"
  }' | jq .
# HTTP 200: { "decision": "allow" }
```

#### ⏳ Agente asesor intenta crear ticket (pending_approval)

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/agent-action \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":  { "id": "agent-acme-002", "level": "asesor", "owner_id": "alice", "tenant_id": "acme" },
    "tool":   "ticketing",
    "action": "create"
  }' | jq .
# HTTP 202:
# {
#   "decision": "pending_approval",
#   "required_approver": "alice",
#   "ttl_seconds": 3600,
#   "reason": "action 'create' on tool 'ticketing' by agent level 'asesor' requires explicit human approval"
# }
```

#### ❌ Agente informativo intenta crear ticket (deny)

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/agent-action \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":  { "id": "agent-acme-003", "level": "informativo", "owner_id": "alice", "tenant_id": "acme" },
    "tool":   "ticketing",
    "action": "create"
  }' | jq .
# HTTP 403:
# { "decision": "deny", "reason": "agent level 'informativo' is not permitted to perform 'create' on tool 'ticketing'" }
```

#### ⏳ Agente accionable intenta desplegar (pending_approval — nunca autónomo)

```bash
curl -s -X POST http://localhost:9080/orchestrator/authorize/agent-action \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":  { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
    "tool":   "deployment",
    "action": "deploy"
  }' | jq .
# HTTP 202: pending_approval con required_approver: "alice"
```

### Consulta directa a OPA

```bash
curl -s -X POST http://localhost:8181/v1/data/agents/decision \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "agent":  { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
      "tool":   "deployment",
      "action": "deploy"
    }
  }' | jq .result
```

### Tests automáticos

```bash
docker run --rm \
  -v $(pwd)/opa:/policies \
  openpolicyagent/opa:1.17.1-debug \
  test /policies/agents -v
```

---

## 7. OpenBao + OPA: credenciales delegadas

### Flujo de acceso a secretos

```
Agente
  │
  ▼
Orquestador ──POST /secrets/access──▶ OPA /data/secrets
                                            │
                               ┌───allow────┴───deny───┐
                               ▼                        ▼
                       OpenBao KV                   HTTP 403
                  GET /v1/secret/data/
                  agents/{id}/credentials/{svc}
                               │
                               ▼
                     Credencial devuelta al agente
```

### Política OPA para secretos

OPA valida tres condiciones antes de autorizar:

1. **Path correcto**: el path debe corresponder al propio agente (`agents/{agent_id}/credentials/...`)
2. **Operación permitida**: según el nivel (`informativo/asesor` → solo `read`; `accionable` → `read` y `write`)
3. **On behalf of válido**: el usuario en cuyo nombre actúa el agente debe ser su propietario registrado

La política se encuentra definida en [`secrets/policy.rego`](../opa/secrets/policy.rego) y se estructura del siguiente modo:
- Definición de las operaciones permitidas por nivel de agente.
```rego
allowed_ops_by_level := {
  "informativo": {"read"},
  "asesor":      {"read"},
  "accionable":  {"read", "write"}
}
```
- Validación del path del secreto: debe corresponder al propio agente (`agents/{agent_id}/credentials/...`).
```rego
expected_path_prefix(agent_id) := sprintf("agents/%v/credentials/", [agent_id])

_valid_agent_path if {
  prefix := expected_path_prefix(input.agent.id)
  startswith(input.secret_path, prefix)
}
```
- Definición de las reglas. `allow` combina las tres condiciones: path válido, operación permitida para el nivel y `on_behalf_of` coincidente con el propietario del agente.
```rego
default allow := false

allow if {
  _valid_agent_path
  _operation_permitted
  _on_behalf_valid
}
```

### Ejemplo de uso

> Igual que en las dos secciones anteriores, todas las llamadas pasan por APISIX con `Authorization: Bearer <token>` obligatorio; la decisión de OPA sigue dependiendo únicamente de `agent`, `secret_path`, `operation` y `on_behalf_of` del body, no de la identidad del usuario autenticado.

#### ✓ Agente accionable lee credenciales de Jira (allow)

```bash
curl -s -X POST http://localhost:9080/orchestrator/secrets/access \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":        { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
    "secret_path":  "agents/agent-acme-001/credentials/jira",
    "operation":    "read",
    "on_behalf_of": "alice"
  }' | jq .
# {
#   "allowed": true,
#   "data": {
#     "url":      "https://acme.atlassian.net",
#     "username": "alice@acme.com",
#     "api_token": "jira-demo-token-alice-001"
#   }
# }
```

#### ❌ Agente intenta leer credenciales de otro agente (deny)

```bash
curl -s -X POST http://localhost:9080/orchestrator/secrets/access \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":        { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
    "secret_path":  "agents/agent-acme-002/credentials/confluence",
    "operation":    "read",
    "on_behalf_of": "alice"
  }' | jq .
# 403: { "reason": "agent cannot access credentials of another agent" }
```

#### ❌ on_behalf_of incorrecto (deny)

```bash
curl -s -X POST http://localhost:9080/orchestrator/secrets/access \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":        { "id": "agent-acme-001", "level": "accionable", "owner_id": "alice", "tenant_id": "acme" },
    "secret_path":  "agents/agent-acme-001/credentials/jira",
    "operation":    "read",
    "on_behalf_of": "eve"
  }' | jq .
# 403: { "reason": "agent owner 'alice' does not match on_behalf_of user 'eve'" }
```

#### ❌ Agente asesor intenta escribir credenciales (deny)

```bash
curl -s -X POST http://localhost:9080/orchestrator/secrets/access \
  -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent":        { "id": "agent-acme-002", "level": "asesor", "owner_id": "alice", "tenant_id": "acme" },
    "secret_path":  "agents/agent-acme-002/credentials/confluence",
    "operation":    "write",
    "on_behalf_of": "alice",
    "secret_data":  { "api_token": "new-token" }
  }' | jq .
# 403: { "reason": "agent level 'asesor' cannot perform 'write' on secrets" }
```

---

## 8. Comparativa OPA vs Keycloak Authorization Services

### Keycloak Authorization Services

Keycloak incluye un subsistema de autorización basado en UMA 2.0 con:
- **Recursos** y **scopes** definidos en el cliente
- **Políticas** de tipo: Role, User, Time, JS (scripted), Aggregated
- **Permission Tickets** para flujos delegados (UMA)
- Evaluación vía endpoint `/realms/{realm}/protocol/openid-connect/token` o introspección

**Referencia**: https://www.keycloak.org/docs/latest/authorization_services/

### Tabla comparativa

| Criterio | OPA + Rego | Keycloak AuthZ Services |
|----------|------------|------------------------|
| **Modelo de política** | Rego (datalog-like, Turing-completo) | UMA + Role/JS policies |
| **Input enriquecido (ABAC)** | Cualquier JSON arbitrario | Requiere custom claim mappers o llamadas adicionales |
| **Decisión ternaria** | Nativo (cualquier output de Rego) | No soportado; solo permit/deny |
| **Multi-tenant** | Nativo en la política Rego | Requiere realms separados o claims específicos |
| **Testing de políticas** | `opa test` integrado, TDD posible | No hay testing nativo de políticas |
| **Versionado** | Git + bundles, mismos flujos que código | Exportación de realm JSON, sin historial nativo |
| **Desacoplamiento** | Total: las políticas son un artefacto independiente | Parcial: políticas acopladas al realm de Keycloak |
| **Curva de aprendizaje** | Alta (Rego es un lenguaje propio) | Media (UMA tiene conceptos específicos) |
| **Ecosistema** | requiere plugins para APISIX | Solo ecosistema Keycloak |
| **Auditoría** | Decision log nativo (JSON) | Log de eventos de Keycloak |
| **Políticas complejas** | Excelente (joins sobre datos externos, recursión) | Limitado (JS policies tienen restricciones) |
| **Datos externos en política** | `http.send()`, data documents | No soportado sin extensiones custom |

### Cuándo elegir cada opción

#### Elegir **Keycloak Authorization Services** cuando:
- El modelo de permisos es RBAC puro o RBAC con scopes simples
- El equipo es pequeño y no quiere mantener un componente adicional
- La complejidad de las políticas cabe en "si tiene el rol X puede acceder al recurso Y"
- No se necesitan decisiones fuera del flujo de autenticación estándar
- Se quiere minimizar la infraestructura (menos servicios = menos operación)

#### Elegir **OPA** cuando:
- Las políticas requieren ABAC: múltiples atributos del contexto, del recurso, del usuario
- Se necesitan decisiones con más de dos estados (ternary, multi-value outputs)
- El modelo es multi-tenant con aislamiento complejo entre tenants
- Las políticas deben versionarse y testearse como código de primera clase
- Hay múltiples sistemas (gateway, orquestador, Kubernetes, etc.) que deben compartir el mismo motor de políticas
- Las políticas necesitan datos externos (consultar un inventario, un CMDB, etc.)
- El equipo quiere auditoría reproducible de cada decisión de autorización

#### Para esta plataforma de IA específicamente

La elección es **OPA** sin ambigüedad por tres razones concretas:

1. **Decisión ternaria para agentes**: Keycloak no puede devolver `pending_approval` con metadatos. Esta semántica es fundamental para el modelo de aprobación humana.
2. **Input enriquecido a runtime**: la visibilidad de una knowledge base (global/tenant/team/private) + sensibilidad + propósito de uso no son atributos estáticos de un token. OPA permite componerlos en el momento de la decisión.
3. **Agentes como identidades de servicio con propietario**: el modelo `(agente × herramienta × acción) → decisión` no se puede expresar en UMA sin código JavaScript custom dentro de Keycloak, que además sería inauditable y difícil de testear.

---

## 9. Referencias y documentación oficial

### OPA
- [Documentación oficial de OPA](https://www.openpolicyagent.org/docs/latest/)
- [Referencia del lenguaje Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Bundles](https://www.openpolicyagent.org/docs/latest/management-bundles/)
- [Decision Logs](https://www.openpolicyagent.org/docs/latest/management-decision-logs/)
- [Plugin OPA para Apache APISIX](https://apisix.apache.org/docs/apisix/plugins/opa/)
- [OPA en el ecosistema CNCF](https://www.cncf.io/projects/open-policy-agent/)

### Apache APISIX
- [Documentación oficial de APISIX](https://apisix.apache.org/docs/apisix/getting-started/)
- [Plugin openid-connect](https://apisix.apache.org/docs/apisix/plugins/openid-connect/)
- [Plugin serverless-pre-function / serverless-post-function](https://apisix.apache.org/docs/apisix/plugins/serverless/) (opción A de la sección 3, no usada en este repo)
- [Admin API de APISIX](https://apisix.apache.org/docs/apisix/admin-api/)

### Keycloak
- [Documentación oficial de Keycloak](https://www.keycloak.org/documentation)
- [Keycloak Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/)
- [Importación de realm en Keycloak 26](https://www.keycloak.org/server/importExport)
- [Protocol Mappers (custom claims)](https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers)

### OpenBao
- [Documentación oficial de OpenBao](https://openbao.org/docs/)
- [KV Secrets Engine v2](https://openbao.org/docs/secrets/kv/kv-v2/)
- [Comparativa OpenBao vs HashiCorp Vault](https://openbao.org/blog/2024/openbao-divergence/)

### Estándares y frameworks
- [UMA 2.0 (User-Managed Access)](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
- [ABAC (Attribute-Based Access Control) — NIST SP 800-162](https://csrc.nist.gov/publications/detail/sp/800-162/final)
- [OAuth 2.0 Token Introspection — RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
