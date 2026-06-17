# PoC: Autorización con OPA + Apache APISIX + Keycloak + OpenBao

PoC de autorización para una plataforma de IA con agentes, que combina **Apache APISIX** (gateway), **OPA** (motor de políticas Rego), **Keycloak** (IdP/JWT) y **OpenBao** (gestión de secretos). Cubre autorización coarse-grained en el gateway, fine-grained (ABAC) en el orquestador, control de scopes de agentes con decisión ternaria (`allow` / `pending_approval` / `deny`) y entrega de credenciales delegadas.

Para el detalle completo de cada fase, walkthroughs, comparativa con Keycloak Authorization Services y troubleshooting, ver [`docs/poc-guide.md`](docs/poc-guide.md).

## Arquitectura general

```
┌──────────────┐        ┌─────────────────────────────────────────────────┐
│   Cliente    │──JWT──▶│               Apache APISIX                     │
│  (usuario /  │        │  plugin: openid-connect (Keycloak)              │
│   agente)    │        │  plugin: opa ──▶ OPA /data/gateway              │
└──────────────┘        │         (coarse-grained: rol + tenant + ruta)   │
                        └───────────────────┬─────────────────────────────┘
                                            │ ruta al upstream correcto
                        ┌───────────────────▼──────────────────────────────┐
                        │           Orquestador de Agentes                 │
                        │  POST /v1/data/orchestrator ──▶ OPA              │
                        │  (fine-grained: ABAC, visibilidad, sensibilidad) │
                        │  POST /v1/data/agents ──▶ OPA                    │
                        │  (scopes: allow | deny | pending_approval)       │
                        │  POST /v1/data/secrets ──▶ OPA                   │
                        │  (credenciales delegadas ──▶ OpenBao)            │
                        └──────────────────────────────────────────────────┘

  ┌──────────────┐   ┌─────────┐   ┌──────────────┐
  │   Keycloak   │   │   OPA   │   │   OpenBao    │
  │  (IdP/JWT)   │   │ (Rego)  │   │ (KV secrets) │
  └──────────────┘   └─────────┘   └──────────────┘
```

### Flujo de una petición

1. El cliente se autentica en Keycloak y obtiene un JWT con claims: `sub`, `tenant_id`, `team_id`, `realm_roles`.
2. La petición llega a APISIX con `Authorization: Bearer <JWT>`.
3. El plugin `openid-connect` valida el JWT contra Keycloak (introspection o JWKS).
4. El plugin `opa` envía la petición a OPA (`/v1/data/gateway`), que decodifica el JWT con `io.jwt.decode`.
5. OPA evalúa la política coarse-grained: ¿el rol está permitido para esta ruta y método?
6. Si OPA devuelve `{"result": {"allow": true}}`, APISIX enruta al backend.
7. El orquestador, antes de actuar, consulta OPA con input enriquecido para decisiones fine-grained.
8. Para ejecutar herramientas externas, el orquestador consulta OPA y, si permite, obtiene credenciales de OpenBao.

## Estructura del proyecto

```
opa-apisix-keycloak/
├── docker-compose.yml      # Orquesta los 8 servicios (Keycloak, APISIX, OPA, OpenBao, orquestador...)
├── apisix/
│   ├── config.yaml         # Config de APISIX (admin API, plugins habilitados)
│   └── entrypoint.sh       # Copia config.yaml antes de arrancar (el montado es :ro)
├── keycloak/
│   └── realm-export.json   # Realm "ai-platform": clientes, roles, usuarios demo y protocol mappers
├── opa/                    # Una carpeta por paquete Rego, cada una con su policy.rego + policy_test.rego
│   ├── gateway/             #   Fase 1 — coarse-grained (rol + tenant + ruta)
│   ├── orchestrator/        #   Fase 2 — ABAC fine-grained (visibilidad, sensibilidad)
│   ├── agents/               #   Fase 3 — scopes de agentes (decisión ternaria)
│   └── secrets/              #   Fase 4 — credenciales delegadas vía OpenBao
├── orchestrator/
│   ├── app.py               # Mock del orquestador de agentes (FastAPI)
│   └── Dockerfile
├── mock-backend/
│   └── nginx.conf           # Upstream de las rutas /api/* del gateway (respuestas JSON fijas)
├── openbao/
│   └── config.hcl
├── scripts/
│   ├── init-apisix.sh        # Crea upstreams y rutas en APISIX vía Admin API
│   ├── init-openbao.sh       # Habilita KV v2 y carga credenciales de demo
│   └── get-token.sh          # Obtiene un JWT de Keycloak para un usuario (password grant)
├── postman/                  # Colección Postman con todos los walkthroughs (ver postman/README.md)
├── docs/
│   └── poc-guide.md          # Guía completa: arquitectura, walkthroughs, Rego, troubleshooting
└── README.md                 # Este fichero
```

## Arrancar el stack

### Prerrequisitos

- Docker ≥ 24 con Docker Compose v2
- `curl`, `jq` (para los walkthroughs)
- Puertos libres: 8080, 8181, 8200, 9080, 9090, 9092

> El orquestador (puerto interno 8000) no se publica al host: solo es alcanzable desde APISIX (`/orchestrator/*`), que valida el JWT antes de reenviar la petición. Ver detalle en [`docs/poc-guide.md`](docs/poc-guide.md).

### Levantar los servicios

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

A partir de aquí, ver [`docs/poc-guide.md`](docs/poc-guide.md) para los walkthroughs de cada fase (coarse-grained, ABAC fine-grained, scopes de agentes, credenciales delegadas), la guía de testing de Rego y el troubleshooting.

## Accesos a dashboards

| Servicio | URL | Usuario / Token | Notas |
|----------|-----|------------------|-------|
| **Keycloak** (consola de administración) | http://localhost:8080 | usuario: `admin` / contraseña: `admin` | Definido en `docker-compose.yml` (`KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`). Realm de la PoC: `ai-platform`. |


