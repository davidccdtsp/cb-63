# Colección Postman

Importar `opa-apisix-keycloak.postman_collection.json` en Postman (File → Import). Todas las variables (URLs, credenciales, client_id/secret) están definidas como **variables de colección**, no requiere importar un environment aparte.

## Uso

1. Levantar el stack (ver `README.md` raíz) y ejecutar `init-apisix.sh` / `init-openbao.sh`.
2. Ejecutar las peticiones de la carpeta **`00 - Auth (Impersonacion)`**: cada una hace un *Resource Owner Password Credentials grant* contra Keycloak (igual que `scripts/get-token.sh`) y guarda el JWT en las variables de colección `token_alice`, `token_bob`, `token_carol` mediante un script de test.
3. Una vez obtenidos los tokens, el resto de carpetas (`01`–`05`) ya pueden ejecutarse: usan esas variables en sus headers `Authorization: Bearer {{token_alice}}`.

Si los tokens expiran, basta con volver a ejecutar las peticiones de `Get Token` de la carpeta 00.
